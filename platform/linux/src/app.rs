//! The desktop window (ui-spec.html "Desktop layout"): a sidebar with Send,
//! Receive, Activity, Devices and Settings, a content pane, centered dialogs for
//! decisions, and drag-and-drop anywhere to start a send.
//!
//! Engine callbacks arrive on the [`Event`] channel and are applied on the GTK
//! main loop; engine calls run on the engine's runtime and are awaited here.

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use adw::prelude::*;
use dfte_core::{Direction, EngineError, IncomingOffer, SendTarget, Transfer, TransferState, VerifyRequest};
use discovery::nm::{JoinedGroup, NmP2p};
use discovery::{Peer, PeerHandle};
use gtk::{gdk, gio, glib};

use crate::engine::{Engine, Event};
use crate::text;

const APP_ID: &str = "dev.dfte.Dfte";
const PAGES: [(&str, &str, &str); 5] = [("send", "Send", "document-send-symbolic"), ("receive", "Receive", "folder-download-symbolic"), ("activity", "Activity", "view-list-symbolic"), ("devices", "Devices", "computer-symbolic"), ("settings", "Settings", "emblem-system-symbolic")];

pub fn run() -> glib::ExitCode {
    // GApplication rejects unknown options unless it handles the command line;
    // `--page` is read in `build`.
    let app = adw::Application::builder().application_id(APP_ID).flags(gio::ApplicationFlags::HANDLES_COMMAND_LINE).build();
    app.connect_command_line(|app, _| {
        app.activate();
        glib::ExitCode::SUCCESS
    });
    app.connect_activate(|app| {
        // Activating again (a second launch) just raises the window.
        if let Some(w) = app.active_window() {
            w.present();
            return;
        }
        match Engine::start() {
            Ok((engine, events)) => Ui::build(app, engine, events),
            Err(msg) => fatal(app, &msg),
        }
    });
    app.run()
}

/// The engine could not start (identity unreadable, ...): say why and quit.
fn fatal(app: &adw::Application, msg: &str) {
    let w = adw::ApplicationWindow::builder().application(app).default_width(480).default_height(240).build();
    w.present();
    let d = adw::AlertDialog::new(Some("DFTE can't start"), Some(msg));
    d.add_response("quit", "Quit");
    let app = app.clone();
    d.connect_response(None, move |_, _| app.quit());
    d.present(Some(&w));
}

struct JobRow {
    row: gtk::ListBoxRow,
    title: gtk::Label,
    sub: gtk::Label,
    bar: gtk::ProgressBar,
    line: gtk::Label,
    rate: gtk::Label,
    actions: gtk::Box,
    last: Option<Transfer>,
    /// Shown buttons depend on direction and state; rebuilt only when that changes.
    shown: Option<(Direction, TransferState)>,
}

struct Ui {
    app: adw::Application,
    engine: Engine,
    window: adw::ApplicationWindow,
    toasts: adw::ToastOverlay,
    split: adw::NavigationSplitView,
    stack: gtk::Stack,
    nav: gtk::ListBox,
    activity_count: gtk::Label,
    listen: Cell<Option<SocketAddr>>,
    // Send
    picked: RefCell<Vec<PathBuf>>,
    picked_label: gtk::Label,
    drop_zone: gtk::Box,
    peers: RefCell<HashMap<PeerHandle, Peer>>,
    peer_list: gtk::ListBox,
    peer_hint: gtk::Label,
    address: gtk::Entry,
    send_button: gtk::Button,
    // Receive
    receive_rows: gtk::ListBox,
    wfd_entry: gtk::Entry,
    wfd_button: gtk::Button,
    wfd_status: gtk::Label,
    wfd: RefCell<Option<(NmP2p, JoinedGroup)>>,
    // Activity
    active: gtk::ListBox,
    earlier: gtk::ListBox,
    activity_empty: gtk::Label,
    jobs: RefCell<HashMap<String, JobRow>>,
    /// What a job is about ("holiday.mp4", "3 items"), set when it starts.
    labels: RefCell<HashMap<String, String>>,
    /// Sender named in an incoming offer, until the job's snapshot carries it.
    offer_peers: RefCell<HashMap<String, String>>,
    // Devices
    devices: gtk::ListBox,
}

impl Ui {
    fn build(app: &adw::Application, engine: Engine, events: async_channel::Receiver<Event>) {
        load_css();
        let window = adw::ApplicationWindow::builder().application(app).title("DFTE").default_width(1120).default_height(700).width_request(360).height_request(480).build();

        let stack = gtk::Stack::builder().transition_type(gtk::StackTransitionType::Crossfade).transition_duration(200).build();
        let nav = gtk::ListBox::builder().css_classes(["navigation-sidebar", "dfte-nav"]).build();
        let activity_count = gtk::Label::builder().css_classes(["count"]).build();
        for (id, title, icon) in PAGES {
            let row_box = gtk::Box::builder().spacing(10).build();
            row_box.append(&gtk::Image::from_icon_name(icon));
            row_box.append(&gtk::Label::builder().label(title).xalign(0.0).hexpand(true).build());
            if id == "activity" {
                row_box.append(&activity_count);
            }
            let row = gtk::ListBoxRow::builder().child(&row_box).name(id).build();
            nav.append(&row);
        }

        let toasts = adw::ToastOverlay::new();
        // Spec: a 224 px sidebar.
        let split = adw::NavigationSplitView::builder().min_sidebar_width(200.0).max_sidebar_width(240.0).build();

        let ui = Rc::new(Self { app: app.clone(), engine, window: window.clone(), toasts: toasts.clone(), split: split.clone(), stack: stack.clone(), nav: nav.clone(), activity_count, listen: Cell::new(None), picked: RefCell::new(Vec::new()), picked_label: gtk::Label::builder().xalign(0.0).css_classes(["dfte-head"]).build(), drop_zone: gtk::Box::builder().orientation(gtk::Orientation::Vertical).spacing(12).css_classes(["dfte-drop"]).build(), peers: RefCell::new(HashMap::new()), peer_list: gtk::ListBox::builder().css_classes(["dfte-card"]).selection_mode(gtk::SelectionMode::Single).build(), peer_hint: caption("Looking for devices… Open DFTE on the other device and choose Receive."), address: gtk::Entry::builder().placeholder_text("Address, e.g. 192.168.1.20:47821").hexpand(true).build(), send_button: pill("Send", "suggested-action"), receive_rows: gtk::ListBox::builder().css_classes(["dfte-card"]).selection_mode(gtk::SelectionMode::None).build(), wfd_entry: gtk::Entry::builder().placeholder_text("Phone name, e.g. Galaxy A30").hexpand(true).build(), wfd_button: pill("Connect", "secondary"), wfd_status: caption("The phone needs DFTE open on Send or Receive. No router involved."), wfd: RefCell::new(None), active: gtk::ListBox::builder().css_classes(["dfte-card"]).selection_mode(gtk::SelectionMode::None).build(), earlier: gtk::ListBox::builder().css_classes(["dfte-card"]).selection_mode(gtk::SelectionMode::None).build(), activity_empty: caption("Nothing yet. Transfers you send or receive show up here."), jobs: RefCell::new(HashMap::new()), labels: RefCell::new(HashMap::new()), offer_peers: RefCell::new(HashMap::new()), devices: gtk::ListBox::builder().css_classes(["dfte-card"]).selection_mode(gtk::SelectionMode::None).build() });

        stack.add_named(&ui.send_page(), Some("send"));
        stack.add_named(&ui.receive_page(), Some("receive"));
        stack.add_named(&ui.activity_page(), Some("activity"));
        stack.add_named(&ui.devices_page(), Some("devices"));
        stack.add_named(&ui.settings_page(), Some("settings"));

        // Sidebar: places on top, this device at the bottom.
        let sidebar = gtk::Box::builder().orientation(gtk::Orientation::Vertical).build();
        sidebar.append(&gtk::ScrolledWindow::builder().child(&nav).vexpand(true).hscrollbar_policy(gtk::PolicyType::Never).build());
        sidebar.append(&ui.me_card());
        let side_view = adw::ToolbarView::new();
        side_view.add_top_bar(&adw::HeaderBar::new());
        side_view.set_content(Some(&sidebar));
        split.set_sidebar(Some(&adw::NavigationPage::new(&side_view, "DFTE")));

        let content_view = adw::ToolbarView::new();
        content_view.add_top_bar(&adw::HeaderBar::new());
        content_view.set_content(Some(&stack));
        let content_page = adw::NavigationPage::new(&content_view, "Send");
        split.set_content(Some(&content_page));
        toasts.set_child(Some(&split));
        window.set_content(Some(&toasts));

        // Narrow windows: sidebar and content become two navigation pages.
        if let Ok(cond) = adw::BreakpointCondition::parse("max-width: 600sp") {
            let bp = adw::Breakpoint::new(cond);
            bp.add_setter(&split, "collapsed", Some(&true.to_value()));
            window.add_breakpoint(bp);
        }

        {
            let ui2 = Rc::clone(&ui);
            nav.connect_row_selected(move |_, row| {
                let Some(row) = row else { return };
                let id = row.widget_name();
                ui2.stack.set_visible_child_name(&id);
                if let Some((_, title, _)) = PAGES.iter().find(|(p, ..)| *p == id.as_str()) {
                    content_page.set_title(title);
                }
                ui2.split.set_show_content(true);
                if id == "devices" {
                    ui2.refresh_devices();
                }
            });
        }
        // `dfte-gtk [--page NAME] [FILE...]`: open on a page (default Send), with
        // files preselected ("Open with DFTE" from a file manager).
        let (start, files) = parse_args(std::env::args().skip(1));
        ui.go_to(&start);
        ui.add_picked(files);
        if !start.is_empty() {
            ui.go_to(&start);
        }

        ui.install_drop_target();
        ui.connect_close();

        // Engine events, applied on the main loop in order.
        {
            let ui2 = Rc::clone(&ui);
            glib::spawn_future_local(async move {
                while let Ok(ev) = events.recv().await {
                    ui2.on_event(ev);
                }
            });
        }
        ui.go_online();
        window.present();
    }

    // ---- pages ---------------------------------------------------------------

    fn send_page(self: &Rc<Self>) -> gtk::Widget {
        let left = vbox(12);
        left.append(&title("Send"));
        left.append(&caption("Drop files anywhere, then pick a device."));

        self.drop_zone.set_valign(gtk::Align::Start);
        self.drop_zone.append(&gtk::Image::builder().icon_name("folder-open-symbolic").pixel_size(32).css_classes(["dim-label"]).build());
        self.drop_zone.append(&gtk::Label::builder().label("Drop files or folders").css_classes(["dfte-head"]).build());
        let or = caption("or");
        or.set_xalign(0.5);
        self.drop_zone.append(&or);
        let pick_row = gtk::Box::builder().spacing(8).halign(gtk::Align::Center).build();
        let files = pill("Choose files", "secondary");
        let folder = pill("Choose folder", "secondary");
        pick_row.append(&files);
        pick_row.append(&folder);
        self.drop_zone.append(&pick_row);
        left.append(&self.drop_zone);
        left.append(&self.picked_label);
        {
            let ui = Rc::clone(self);
            files.connect_clicked(move |_| ui.choose_files());
        }
        {
            let ui = Rc::clone(self);
            folder.connect_clicked(move |_| ui.choose_folder());
        }

        let right = vbox(12);
        let nearby = gtk::Box::builder().spacing(6).build();
        nearby.append(&label("Nearby"));
        nearby.append(&gtk::Spinner::builder().spinning(true).build());
        right.append(&nearby);
        right.append(&self.peer_hint);
        right.append(&self.peer_list);
        self.peer_list.set_visible(false);
        right.append(&label("Or type an address"));
        right.append(&self.address);
        right.append(&gtk::Box::builder().vexpand(true).build());
        self.send_button.set_sensitive(false);
        right.append(&self.send_button);
        {
            let ui = Rc::clone(self);
            self.peer_list.connect_row_selected(move |_, _| ui.update_send_button());
        }
        {
            let ui = Rc::clone(self);
            self.address.connect_changed(move |e| {
                if !e.text().is_empty() {
                    ui.peer_list.unselect_all();
                }
                ui.update_send_button();
            });
        }
        {
            let ui = Rc::clone(self);
            self.send_button.connect_clicked(move |_| ui.send());
        }

        let columns = gtk::Box::builder().spacing(24).homogeneous(true).css_classes(["dfte-page"]).build();
        columns.append(&left);
        columns.append(&right);
        // Below ~860 px of *content* the two columns stack (ui-spec); the window
        // also holds the 240 px sidebar, hence 1100.
        if let Ok(cond) = adw::BreakpointCondition::parse("max-width: 1100sp") {
            let bp = adw::Breakpoint::new(cond);
            bp.add_setter(&columns, "orientation", Some(&gtk::Orientation::Vertical.to_value()));
            self.window.add_breakpoint(bp);
        }
        self.update_picked();
        scrolled(&columns)
    }

    fn receive_page(self: &Rc<Self>) -> gtk::Widget {
        let page = vbox(12);
        page.add_css_class("dfte-page");
        page.append(&title("Receive"));
        page.append(&caption("This computer is always ready to receive while DFTE is open. Senders see it as the name below."));
        page.append(&self.receive_rows);
        page.append(&label("Wi-Fi Direct"));
        page.append(&caption("Connect straight to a phone, without a router. This computer stays on its Wi-Fi."));
        let row = gtk::Box::builder().spacing(8).build();
        row.append(&self.wfd_entry);
        row.append(&self.wfd_button);
        page.append(&row);
        page.append(&self.wfd_status);
        page.append(&caption(&format!("Received files are saved to {}.", downloads().display())));
        {
            let ui = Rc::clone(self);
            self.wfd_button.connect_clicked(move |_| ui.toggle_wifi_direct());
        }
        self.refresh_receive();
        scrolled(&page)
    }

    fn activity_page(self: &Rc<Self>) -> gtk::Widget {
        let page = vbox(12);
        page.add_css_class("dfte-page");
        page.append(&title("Activity"));
        page.append(&self.activity_empty);
        page.append(&self.active);
        let earlier = label("Earlier");
        page.append(&earlier);
        page.append(&self.earlier);
        self.earlier.bind_property("visible", &earlier, "visible").sync_create().build();
        self.active.set_visible(false);
        self.earlier.set_visible(false);
        scrolled(&page)
    }

    fn devices_page(self: &Rc<Self>) -> gtk::Widget {
        let page = vbox(12);
        page.add_css_class("dfte-page");
        page.append(&title("Devices"));
        page.append(&caption("Trusted devices skip the code comparison. Remove one to compare codes again next time."));
        page.append(&self.devices);
        scrolled(&page)
    }

    fn settings_page(self: &Rc<Self>) -> gtk::Widget {
        let page = vbox(12);
        page.add_css_class("dfte-page");
        page.append(&title("Settings"));
        let card = gtk::ListBox::builder().css_classes(["dfte-card"]).selection_mode(gtk::SelectionMode::None).build();
        card.append(&info_row("Device name", &self.engine.device_name, Some("Set DFTE_DEVICE_NAME to change it.")));
        card.append(&info_row("Fingerprint", &self.engine.fingerprint, Some("Other devices show this when you pair.")));
        let dl = downloads();
        let open = pill("Open", "secondary");
        open.add_css_class("small");
        open.set_valign(gtk::Align::Center);
        let row = info_row("Downloads", &dl.display().to_string(), None);
        if let Some(b) = row.child().and_downcast::<gtk::Box>() {
            b.append(&open);
        }
        card.append(&row);
        {
            let ui = Rc::clone(self);
            open.connect_clicked(move |_| ui.open_folder(&dl));
        }
        page.append(&card);
        page.append(&caption("Appearance follows the system light/dark setting."));
        scrolled(&page)
    }

    /// The device card at the bottom of the sidebar.
    fn me_card(&self) -> gtk::Widget {
        let b = gtk::Box::builder().spacing(10).css_classes(["dfte-me"]).build();
        b.append(&avatar(&self.engine.device_name));
        let t = vbox(0);
        t.append(&gtk::Label::builder().label(&self.engine.device_name).xalign(0.0).css_classes(["dfte-label"]).ellipsize(gtk::pango::EllipsizeMode::End).build());
        t.append(&gtk::Label::builder().label(short_fp(&self.engine.fingerprint)).xalign(0.0).css_classes(["dfte-mono"]).build());
        t.set_hexpand(true);
        b.append(&t);
        b.append(&chip("Receiving", "ok"));
        b.upcast()
    }

    // ---- send ----------------------------------------------------------------

    fn choose_files(self: &Rc<Self>) {
        let d = gtk::FileDialog::builder().title("Choose files to send").modal(true).build();
        let ui = Rc::clone(self);
        d.open_multiple(Some(&self.window), gio::Cancellable::NONE, move |r| match r {
            Ok(list) => ui.add_picked(files_of(&list)),
            Err(e) => dialog_error(&e),
        });
    }

    fn choose_folder(self: &Rc<Self>) {
        let d = gtk::FileDialog::builder().title("Choose a folder to send").modal(true).build();
        let ui = Rc::clone(self);
        d.select_folder(Some(&self.window), gio::Cancellable::NONE, move |r| match r {
            Ok(f) => ui.add_picked(f.path().into_iter().collect()),
            Err(e) => dialog_error(&e),
        });
    }

    fn add_picked(&self, paths: Vec<PathBuf>) {
        if paths.is_empty() {
            return;
        }
        {
            let mut p = self.picked.borrow_mut();
            for x in paths {
                if !p.contains(&x) {
                    p.push(x);
                }
            }
        }
        self.update_picked();
        self.go_to("send");
    }

    fn update_picked(&self) {
        let p = self.picked.borrow();
        if p.is_empty() {
            self.picked_label.set_visible(false);
        } else {
            let bytes: u64 = p.iter().map(|x| tree_size(x)).sum();
            let name = if p.len() == 1 { p[0].file_name().map_or_else(|| p[0].display().to_string(), |n| n.to_string_lossy().into_owned()) } else { format!("{} items", p.len()) };
            self.picked_label.set_label(&format!("{name}  ·  {}", text::items(p.len(), bytes)));
            self.picked_label.set_visible(true);
        }
        drop(p);
        self.update_send_button();
    }

    fn selected_peer(&self) -> Option<Peer> {
        let row = self.peer_list.selected_row()?;
        let handle = PeerHandle::new(row.widget_name().as_str());
        self.peers.borrow().get(&handle).cloned()
    }

    fn update_send_button(&self) {
        let target = match self.selected_peer() {
            Some(p) => Some(dfte_cli::offer::printable(&p.display_name)),
            None => Some(self.address.text().trim().to_owned()).filter(|a| !a.is_empty()),
        };
        let ready = !self.picked.borrow().is_empty() && target.is_some();
        self.send_button.set_sensitive(ready);
        self.send_button.set_label(&match target {
            Some(t) if ready => format!("Send to {t}"),
            _ => "Send".to_owned(),
        });
    }

    fn send(self: &Rc<Self>) {
        let paths = self.picked.borrow().clone();
        let target = match self.selected_peer() {
            Some(p) => SendTarget::Peer(p),
            None => match parse_address(self.address.text().trim()) {
                Ok(addr) => SendTarget::Address { addr, expected_fingerprint: None },
                Err(msg) => return self.toast(&msg),
            },
        };
        let what = if paths.len() == 1 { paths[0].file_name().map_or_else(|| "1 item".into(), |n| n.to_string_lossy().into_owned()) } else { format!("{} items", paths.len()) };
        let m = std::sync::Arc::clone(&self.engine.manager);
        let handle = self.engine.spawn(async move { m.send_files(target, paths).await });
        let ui = Rc::clone(self);
        glib::spawn_future_local(async move {
            match handle.await {
                Ok(Ok(id)) => {
                    ui.labels.borrow_mut().insert(id.clone(), what);
                    ui.picked.borrow_mut().clear();
                    ui.address.set_text("");
                    ui.update_picked();
                    ui.ensure_row(&id);
                    ui.go_to("activity");
                }
                Ok(Err(e)) => ui.toast(&dfte_cli::error::engine_message(&e, None)),
                Err(e) => ui.toast(&format!("Could not start the transfer: {e}")),
            }
        });
    }

    fn install_drop_target(self: &Rc<Self>) {
        let drop = gtk::DropTarget::new(gdk::FileList::static_type(), gdk::DragAction::COPY);
        {
            let ui = Rc::clone(self);
            drop.connect_enter(move |_, _, _| {
                ui.drop_zone.add_css_class("active");
                gdk::DragAction::COPY
            });
        }
        {
            let ui = Rc::clone(self);
            drop.connect_leave(move |_| ui.drop_zone.remove_css_class("active"));
        }
        {
            let ui = Rc::clone(self);
            drop.connect_drop(move |_, value, _, _| {
                ui.drop_zone.remove_css_class("active");
                match value.get::<gdk::FileList>() {
                    Ok(list) => {
                        ui.add_picked(list.files().iter().filter_map(gio::prelude::FileExt::path).collect());
                        true
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "drop without files");
                        false
                    }
                }
            });
        }
        self.window.add_controller(drop);
    }

    // ---- receive / Wi-Fi Direct ------------------------------------------------

    fn go_online(self: &Rc<Self>) {
        let m = std::sync::Arc::clone(&self.engine.manager);
        let handle = self.engine.spawn(Engine::go_online(m));
        let ui = Rc::clone(self);
        glib::spawn_future_local(async move {
            match handle.await {
                Ok(Ok(addr)) => {
                    ui.listen.set(Some(addr));
                    ui.refresh_receive();
                }
                Ok(Err(e)) => ui.toast(&format!("Not reachable by other devices: {}", dfte_cli::error::engine_message(&e, None))),
                Err(e) => ui.toast(&format!("Not reachable by other devices: {e}")),
            }
        });
    }

    fn refresh_receive(&self) {
        while let Some(r) = self.receive_rows.row_at_index(0) {
            self.receive_rows.remove(&r);
        }
        let port = self.listen.get().map(|a| a.port());
        let mut addrs: Vec<String> = Vec::new();
        if let (Some(ip), Some(p)) = (text::default_ipv4(), port) {
            addrs.push(format!("{ip}:{p}"));
        }
        if let (Some((_, g)), Some(p)) = (self.wfd.borrow().as_ref(), port)
            && let Some(ip) = g.local_ip
        {
            addrs.push(format!("{ip}:{p} (Wi-Fi Direct)"));
        }
        let status = if port.is_some() { format!("Visible as {}", self.engine.device_name) } else { "Starting…".to_owned() };
        self.receive_rows.append(&info_row("Status", &status, None));
        self.receive_rows.append(&info_row("Address", &if addrs.is_empty() { "Not connected to a network".to_owned() } else { addrs.join("   ") }, Some("For devices that don't show up: type this on the sending device.")));
        self.receive_rows.append(&info_row("Fingerprint", &self.engine.fingerprint, None));
    }

    fn toggle_wifi_direct(self: &Rc<Self>) {
        if let Some((nm, g)) = self.wfd.borrow_mut().take() {
            self.wfd_status.set_label("Leaving the Wi-Fi Direct group…");
            let h = self.engine.spawn(async move { nm.leave(&g).await });
            let ui = Rc::clone(self);
            glib::spawn_future_local(async move {
                let msg = match h.await {
                    Ok(Ok(())) => "Disconnected.".to_owned(),
                    Ok(Err(e)) => format!("Could not leave the group: {e}. It ends when the phone stops hosting."),
                    Err(e) => format!("Could not leave the group: {e}"),
                };
                ui.wfd_status.set_label(&msg);
                ui.wfd_button.set_label("Connect");
                ui.refresh_receive();
            });
            return;
        }
        let wanted = self.wfd_entry.text().trim().to_owned();
        if wanted.is_empty() {
            return self.toast("Type the phone's name as it appears in its Wi-Fi Direct settings.");
        }
        self.wfd_button.set_sensitive(false);
        self.wfd_status.set_label(&format!("Looking for “{wanted}”… accept the request on the phone if it asks."));
        let m = std::sync::Arc::clone(&self.engine.manager);
        let h = self.engine.spawn(async move {
            let nm = NmP2p::system().await?;
            let peer = nm.find(&wanted, std::time::Duration::from_secs(20)).await?;
            if let Err(e) = nm.stop_find().await {
                tracing::debug!(error = %e, "StopFind");
            }
            let g = nm.join(&peer, std::time::Duration::from_secs(60)).await?;
            // As a member, announce ourselves to the owner (it answers, §6).
            if let Some(ip) = g.peer_ip
                && let Err(e) = m.add_beacon_target(SocketAddr::new(ip, discovery::lan::DEFAULT_BEACON_PORT))
            {
                tracing::warn!(error = %e, "beacon target");
            }
            Ok::<_, discovery::DiscoveryError>((nm, g, peer.name))
        });
        let ui = Rc::clone(self);
        glib::spawn_future_local(async move {
            ui.wfd_button.set_sensitive(true);
            match h.await {
                Ok(Ok((nm, g, name))) => {
                    ui.wfd_status.set_label(&format!("Connected to {} over Wi-Fi Direct. It now shows up under Send → Nearby.", dfte_cli::offer::printable(&name)));
                    ui.wfd_button.set_label("Disconnect");
                    *ui.wfd.borrow_mut() = Some((nm, g));
                    ui.refresh_receive();
                }
                Ok(Err(e)) => ui.wfd_status.set_label(&wfd_message(&e)),
                Err(e) => ui.wfd_status.set_label(&format!("Wi-Fi Direct failed: {e}")),
            }
        });
    }

    // ---- engine events ---------------------------------------------------------

    fn on_event(self: &Rc<Self>, ev: Event) {
        match ev {
            Event::Progress(t) => self.update_job(t),
            Event::State(id, s) => {
                let snapshot = self.jobs.borrow().get(&id).and_then(|r| r.last.clone());
                let t = snapshot.map(|mut t| {
                    t.state = s;
                    t
                });
                match t {
                    Some(t) => self.update_job(t),
                    None => self.fetch_job(&id),
                }
                if s == TransferState::Completed {
                    self.notify_done(&id);
                }
            }
            Event::PeerFound(p) => {
                self.peers.borrow_mut().insert(p.handle.clone(), p);
                self.refresh_peers();
            }
            Event::PeerLost(h) => {
                self.peers.borrow_mut().remove(&h);
                self.refresh_peers();
            }
            Event::Error(id, e) => self.on_error(id.as_deref(), &e),
            Event::Incoming(o) => self.ask_incoming(o),
            Event::Verify(r) => self.ask_verify(r),
        }
    }

    fn on_error(&self, id: Option<&str>, e: &EngineError) {
        let peer = id.and_then(|i| self.jobs.borrow().get(i).and_then(|r| r.last.as_ref().and_then(|t| t.peer_name.clone())));
        let msg = dfte_cli::error::engine_message(e, peer.as_deref());
        if let Some(i) = id
            && let Some(r) = self.jobs.borrow().get(i)
        {
            r.rate.set_label(&msg);
        }
        self.toast(&msg);
    }

    /// A state change for a job the UI hasn't seen yet: ask for its snapshot.
    fn fetch_job(self: &Rc<Self>, id: &str) {
        let m = std::sync::Arc::clone(&self.engine.manager);
        let id2 = id.to_owned();
        let h = self.engine.spawn(async move { m.transfer(&id2).await });
        let ui = Rc::clone(self);
        glib::spawn_future_local(async move {
            if let Ok(Some(t)) = h.await {
                ui.update_job(t);
            }
        });
    }

    fn refresh_peers(self: &Rc<Self>) {
        let selected = self.selected_peer().map(|p| p.handle);
        while let Some(r) = self.peer_list.row_at_index(0) {
            self.peer_list.remove(&r);
        }
        let trust = self.engine.trust().ok();
        let peers = self.peers.borrow();
        let mut sorted: Vec<&Peer> = peers.values().collect();
        sorted.sort_by_key(|p| p.display_name.to_lowercase());
        for p in sorted {
            let name = dfte_cli::offer::printable(&p.display_name);
            let trusted = p.fingerprint.as_deref().and_then(|f| trust.as_ref().and_then(|t| t.get(f))).is_some();
            let row_box = gtk::Box::builder().spacing(12).build();
            row_box.append(&avatar(&name));
            let t = vbox(0);
            t.set_hexpand(true);
            t.append(&gtk::Label::builder().label(&name).xalign(0.0).build());
            t.append(&caption(if trusted { "Trusted · Nearby" } else { "New device · Nearby" }));
            row_box.append(&t);
            if trusted {
                row_box.append(&gtk::Image::from_icon_name("security-high-symbolic"));
            }
            let row = gtk::ListBoxRow::builder().child(&row_box).name(p.handle.as_str()).build();
            self.peer_list.append(&row);
            if selected.as_ref() == Some(&p.handle) {
                self.peer_list.select_row(Some(&row));
            }
        }
        let any = !peers.is_empty();
        drop(peers);
        self.peer_list.set_visible(any);
        self.peer_hint.set_visible(!any);
        self.update_send_button();
    }

    fn ask_incoming(self: &Rc<Self>, o: IncomingOffer) {
        let (head, body) = text::offer_text(&o);
        // Name the job now: its row appears (as "Waiting") while the dialog is open.
        let what = if o.files.len() == 1 { o.files[0].path.clone() } else { format!("{} items", o.files.len()) };
        self.labels.borrow_mut().insert(o.transfer_id.clone(), dfte_cli::offer::printable(&what));
        self.offer_peers.borrow_mut().insert(o.transfer_id.clone(), dfte_cli::offer::printable(&o.peer_name));
        let d = adw::AlertDialog::new(Some(&head), Some(&body));
        d.add_response("decline", "Decline");
        d.add_response("accept", "Accept");
        d.set_response_appearance("accept", adw::ResponseAppearance::Suggested);
        d.set_default_response(Some("accept"));
        d.set_close_response("decline");
        let ui = Rc::clone(self);
        d.connect_response(None, move |_, resp| {
            let accept = resp == "accept";
            let m = std::sync::Arc::clone(&ui.engine.manager);
            let id = o.transfer_id.clone();
            let h = ui.engine.spawn(async move { if accept { m.accept_incoming(&id, downloads()).await } else { m.reject_incoming(&id).await } });
            let ui2 = Rc::clone(&ui);
            glib::spawn_future_local(async move {
                match h.await {
                    Ok(Ok(())) if accept => ui2.go_to("activity"),
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => ui2.toast(&dfte_cli::error::engine_message(&e, None)),
                    Err(e) => ui2.toast(&e.to_string()),
                }
            });
        });
        self.window.present();
        d.present(Some(&self.window));
    }

    /// Code comparison (manual §12.1). A trusted fingerprint skips it; a first
    /// pairing never does, and there is no "skip" (manual §35).
    fn ask_verify(self: &Rc<Self>, r: VerifyRequest) {
        let trusted = self.engine.trust().ok().and_then(|t| t.get(&r.peer.fingerprint).map(|_| ())).is_some();
        if trusted {
            if let Err(e) = self.engine.manager.confirm_peer(r.request_id, true) {
                self.toast(&format!("Could not confirm a trusted device: {e}"));
            }
            return;
        }
        let name = dfte_cli::offer::printable(&r.peer.device_name);
        let d = adw::AlertDialog::new(Some("Compare this code"), Some(&format!("Check that {name} shows the same six digits.")));
        let extra = vbox(14);
        let digits = gtk::Box::builder().spacing(10).halign(gtk::Align::Center).css_classes(["dfte-sas"]).build();
        for (i, c) in text::sas_digits(&r.peer.sas).into_iter().enumerate() {
            if i == 3 {
                digits.append(&gtk::Box::builder().width_request(10).build());
            }
            digits.append(&gtk::Label::new(Some(&c.to_string())));
        }
        extra.append(&digits);
        extra.append(&gtk::Label::builder().label(&r.peer.fingerprint).css_classes(["dfte-mono"]).selectable(true).build());
        let remember = gtk::CheckButton::with_label("Trust this device (skip the code next time)");
        remember.set_halign(gtk::Align::Center);
        extra.append(&remember);
        d.set_extra_child(Some(&extra));
        d.add_response("reject", "They don't match");
        d.add_response("accept", "Codes match");
        d.set_response_appearance("reject", adw::ResponseAppearance::Destructive);
        d.set_response_appearance("accept", adw::ResponseAppearance::Suggested);
        d.set_close_response("reject");
        let ui = Rc::clone(self);
        d.connect_response(None, move |_, resp| {
            let accept = resp == "accept";
            if let Err(e) = ui.engine.manager.confirm_peer(r.request_id, accept) {
                ui.toast(&format!("The request expired: {e}"));
                return;
            }
            if accept && remember.is_active() {
                match ui.engine.trust() {
                    Ok(mut t) => {
                        let saved = t.add_verified(&r.peer.fingerprint, &r.peer.device_name).map(|_| ()).and_then(|()| t.save());
                        if let Err(e) = saved {
                            ui.toast(&format!("Could not remember this device: {}", e.user_message(None)));
                        }
                    }
                    Err(msg) => ui.toast(&msg),
                }
            }
        });
        self.window.present();
        d.present(Some(&self.window));
    }

    // ---- activity -----------------------------------------------------------------

    fn ensure_row(self: &Rc<Self>, id: &str) {
        if self.jobs.borrow().contains_key(id) {
            return;
        }
        let row_box = vbox(8);
        row_box.add_css_class("dfte-row");
        let top = gtk::Box::builder().spacing(10).build();
        let titles = vbox(0);
        titles.set_hexpand(true);
        let title = gtk::Label::builder().xalign(0.0).css_classes(["dfte-label"]).ellipsize(gtk::pango::EllipsizeMode::Middle).build();
        let sub = caption("");
        titles.append(&title);
        titles.append(&sub);
        top.append(&titles);
        let actions = gtk::Box::builder().spacing(6).valign(gtk::Align::Center).build();
        top.append(&actions);
        row_box.append(&top);
        let bar = gtk::ProgressBar::builder().css_classes(["dfte-bar"]).build();
        row_box.append(&bar);
        let lines = gtk::Box::builder().build();
        let line = caption("");
        line.set_hexpand(true);
        let rate = caption("");
        lines.append(&line);
        lines.append(&rate);
        row_box.append(&lines);
        let row = gtk::ListBoxRow::builder().child(&row_box).activatable(false).build();
        self.active.prepend(&row);
        self.active.set_visible(true);
        self.activity_empty.set_visible(false);
        self.jobs.borrow_mut().insert(id.to_owned(), JobRow { row, title, sub, bar, line, rate, actions, last: None, shown: None });
        self.update_count();
    }

    fn update_job(self: &Rc<Self>, t: Transfer) {
        self.ensure_row(&t.id);
        let mut jobs = self.jobs.borrow_mut();
        let Some(r) = jobs.get_mut(&t.id) else { return };
        let what = self.labels.borrow().get(&t.id).cloned().unwrap_or_else(|| "Transfer".to_owned());
        r.title.set_label(&what);
        let peer = t.peer_name.as_deref().map(dfte_cli::offer::printable).or_else(|| self.offer_peers.borrow().get(&t.id).cloned()).unwrap_or_else(|| "nearby device".to_owned());
        r.sub.set_label(&format!("{} {peer} · {}", if t.direction == Direction::Send { "To" } else { "From" }, text::state_label(t.state)));
        let frac = if t.bytes_total == 0 { 0.0 } else { t.bytes_done as f64 / t.bytes_total as f64 };
        r.bar.set_fraction(frac.clamp(0.0, 1.0));
        r.bar.set_visible(!matches!(t.state, TransferState::Completed | TransferState::Cancelled));
        r.line.set_label(&if t.bytes_total > 0 { text::progress_line(t.bytes_done, t.bytes_total) } else { String::new() });
        if t.state == TransferState::Transferring {
            r.rate.set_label(&text::rate_line(&t));
        } else if matches!(t.state, TransferState::Completed | TransferState::Cancelled | TransferState::Paused) {
            r.rate.set_label("");
        }
        let key = (t.direction, t.state);
        let terminal = !t.state.is_active();
        let moved_to_earlier = terminal && r.row.parent().is_some_and(|p| p == self.active.clone().upcast::<gtk::Widget>());
        if r.shown != Some(key) {
            r.shown = Some(key);
            while let Some(c) = r.actions.first_child() {
                r.actions.remove(&c);
            }
            for (label, kind, action) in actions_for(&t) {
                let b = pill(label, kind);
                b.add_css_class("small");
                let ui = Rc::clone(self);
                let id = t.id.clone();
                b.connect_clicked(move |_| ui.job_action(&id, action));
                r.actions.append(&b);
            }
        }
        r.last = Some(t);
        if moved_to_earlier {
            self.active.remove(&r.row);
            self.earlier.prepend(&r.row);
            self.earlier.set_visible(true);
            self.active.set_visible(self.active.row_at_index(0).is_some());
        }
        drop(jobs);
        self.update_count();
    }

    fn job_action(self: &Rc<Self>, id: &str, action: Action) {
        if action == Action::ShowFolder {
            return self.open_folder(&downloads());
        }
        let m = std::sync::Arc::clone(&self.engine.manager);
        let id2 = id.to_owned();
        let h = self.engine.spawn(async move {
            match action {
                Action::Pause => m.pause(&id2).await,
                Action::Resume => m.resume(&id2).await,
                Action::Cancel => m.cancel(&id2).await,
                Action::ShowFolder => Ok(()),
            }
        });
        let ui = Rc::clone(self);
        let id3 = id.to_owned();
        glib::spawn_future_local(async move {
            match h.await {
                Ok(Ok(())) => {
                    // A resumed job runs again: back to the active list.
                    if action == Action::Resume
                        && let Some(r) = ui.jobs.borrow().get(&id3)
                        && r.row.parent().is_some_and(|p| p == ui.earlier.clone().upcast::<gtk::Widget>())
                    {
                        ui.earlier.remove(&r.row);
                        ui.active.prepend(&r.row);
                        ui.active.set_visible(true);
                    }
                }
                Ok(Err(e)) => ui.toast(&dfte_cli::error::engine_message(&e, None)),
                Err(e) => ui.toast(&e.to_string()),
            }
        });
    }

    fn update_count(&self) {
        let n = self.jobs.borrow().values().filter(|r| r.last.as_ref().is_none_or(|t| t.state.is_active())).count();
        self.activity_count.set_label(&if n == 0 { String::new() } else { n.to_string() });
    }

    /// A desktop notification when a transfer finishes while the window is in
    /// the background (freedesktop notifications work on every desktop, §24).
    fn notify_done(&self, id: &str) {
        if self.window.is_active() {
            return;
        }
        let jobs = self.jobs.borrow();
        let Some(t) = jobs.get(id).and_then(|r| r.last.as_ref()) else { return };
        let what = self.labels.borrow().get(id).cloned().unwrap_or_else(|| "Transfer".to_owned());
        let n = gio::Notification::new(if t.direction == Direction::Receive { "Received" } else { "Sent" });
        n.set_body(Some(&what));
        self.app.send_notification(Some(id), &n);
    }

    // ---- devices -------------------------------------------------------------------

    fn refresh_devices(self: &Rc<Self>) {
        while let Some(r) = self.devices.row_at_index(0) {
            self.devices.remove(&r);
        }
        let store = match self.engine.trust() {
            Ok(s) => s,
            Err(msg) => return self.toast(&msg),
        };
        if store.peers().is_empty() {
            self.devices.append(&info_row("No trusted devices", "Tick “Trust this device” when you compare codes.", None));
            return;
        }
        for p in store.peers() {
            let row = info_row(&dfte_cli::offer::printable(&p.name), &p.fingerprint, None);
            let remove = pill("Remove", "danger");
            remove.add_css_class("small");
            remove.set_valign(gtk::Align::Center);
            let ui = Rc::clone(self);
            let fp = p.fingerprint.clone();
            remove.connect_clicked(move |_| {
                let r = ui.engine.trust().and_then(|mut t| t.remove(&fp).map_err(|e| e.user_message(None)).and_then(|_| t.save().map_err(|e| e.user_message(None))));
                if let Err(msg) = r {
                    ui.toast(&msg);
                }
                ui.refresh_devices();
            });
            if let Some(b) = row.child().and_downcast::<gtk::Box>() {
                b.append(&remove);
            }
            self.devices.append(&row);
        }
    }

    // ---- misc ------------------------------------------------------------------------

    fn go_to(&self, page: &str) {
        let idx = PAGES.iter().position(|(p, ..)| *p == page).and_then(|i| i32::try_from(i).ok()).unwrap_or(0);
        self.nav.select_row(self.nav.row_at_index(idx).as_ref());
    }

    fn toast(&self, msg: &str) {
        self.toasts.add_toast(adw::Toast::builder().title(glib::markup_escape_text(msg)).timeout(5).build());
    }

    fn open_folder(&self, dir: &Path) {
        let l = gtk::FileLauncher::new(Some(&gio::File::for_path(dir)));
        let toasts = self.toasts.clone();
        l.launch(Some(&self.window), gio::Cancellable::NONE, move |r| {
            if let Err(e) = r {
                toasts.add_toast(adw::Toast::new(&glib::markup_escape_text(&format!("Could not open the folder: {e}"))));
            }
        });
    }

    fn connect_close(self: &Rc<Self>) {
        let ui = Rc::clone(self);
        self.app.connect_shutdown(move |_| {
            if let Some((nm, g)) = ui.wfd.borrow_mut().take() {
                let h = ui.engine.spawn(async move { nm.leave(&g).await });
                // Best effort on exit: NetworkManager also drops the volatile
                // connection when the phone stops hosting.
                drop(h);
            }
            ui.engine.shutdown();
        });
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Action {
    Pause,
    Resume,
    Cancel,
    ShowFolder,
}

fn actions_for(t: &Transfer) -> Vec<(&'static str, &'static str, Action)> {
    let send = t.direction == Direction::Send;
    match t.state {
        TransferState::Transferring if send => vec![("Pause", "secondary", Action::Pause), ("Cancel", "danger", Action::Cancel)],
        TransferState::Pending | TransferState::Negotiating | TransferState::Transferring => vec![("Cancel", "danger", Action::Cancel)],
        s if send && s.is_resumable() => vec![("Resume", "secondary", Action::Resume)],
        TransferState::Completed if !send => vec![("Show in folder", "secondary", Action::ShowFolder)],
        _ => Vec::new(),
    }
}

fn wfd_message(e: &discovery::DiscoveryError) -> String {
    use discovery::DiscoveryError as D;
    match e {
        D::UnknownPeer => "No phone with that name was found. Open DFTE on the phone (Send or Receive) and check its Wi-Fi Direct name.".into(),
        D::ConnectionRejected => "The phone declined or dropped the connection.".into(),
        D::Timeout => "The phone did not accept in time.".into(),
        D::PermissionDenied(_) => "NetworkManager refused: this user may not manage Wi-Fi.".into(),
        D::RadioUnavailable(m) => format!("Wi-Fi Direct is unavailable: {m}."),
        other => format!("Wi-Fi Direct failed: {other}."),
    }
}

/// `[--page NAME] [FILE...]` -> (page, files). Unknown options are ignored.
fn parse_args(args: impl Iterator<Item = String>) -> (String, Vec<PathBuf>) {
    let (mut page, mut files) = (String::new(), Vec::new());
    let mut args = args.peekable();
    while let Some(a) = args.next() {
        if a == "--page" {
            page = args.next().unwrap_or_default();
        } else if !a.starts_with("--") {
            files.push(PathBuf::from(a));
        }
    }
    (page, files)
}

fn parse_address(s: &str) -> Result<SocketAddr, String> {
    if let Ok(a) = s.parse::<SocketAddr>() {
        return Ok(a);
    }
    s.parse::<std::net::IpAddr>().map(|ip| SocketAddr::new(ip, crate::engine::PORT)).map_err(|_| format!("“{s}” is not an address. Use the one shown on the other device, e.g. 192.168.1.20:47821."))
}

fn downloads() -> PathBuf {
    dfte_cli::paths::download_dir().unwrap_or_else(|e| {
        tracing::warn!(error = %e.user_message(None), "no download dir; using the home directory");
        std::env::var_os("HOME").map(PathBuf::from).unwrap_or_default()
    })
}

/// Total size of a file or folder (for the selection summary). Unreadable
/// entries count as 0: the engine reports them properly when sending.
fn tree_size(p: &Path) -> u64 {
    match std::fs::symlink_metadata(p) {
        Ok(m) if m.is_dir() => std::fs::read_dir(p).map(|rd| rd.filter_map(Result::ok).map(|e| tree_size(&e.path())).sum()).unwrap_or(0),
        Ok(m) => m.len(),
        Err(_) => 0,
    }
}

fn files_of(list: &gio::ListModel) -> Vec<PathBuf> {
    (0..list.n_items()).filter_map(|i| list.item(i).and_downcast::<gio::File>()).filter_map(|f| f.path()).collect()
}

fn dialog_error(e: &glib::Error) {
    // Dismissing the dialog is not an error.
    if !e.matches(gtk::DialogError::Dismissed) && !e.matches(gtk::DialogError::Cancelled) {
        tracing::warn!(error = %e, "file dialog failed");
    }
}

fn load_css() {
    let Some(display) = gdk::Display::default() else { return };
    let base = gtk::CssProvider::new();
    base.load_from_string(include_str!("../data/style.css"));
    gtk::style_context_add_provider_for_display(&display, &base, gtk::STYLE_PROVIDER_PRIORITY_APPLICATION);
    let dark = gtk::CssProvider::new();
    dark.load_from_string(include_str!("../data/style-dark.css"));
    let sm = adw::StyleManager::default();
    let apply = move |sm: &adw::StyleManager| {
        if sm.is_dark() {
            gtk::style_context_add_provider_for_display(&display, &dark, gtk::STYLE_PROVIDER_PRIORITY_APPLICATION + 1);
        } else {
            gtk::style_context_remove_provider_for_display(&display, &dark);
        }
    };
    apply(&sm);
    sm.connect_dark_notify(apply);
}

// ---- small widget helpers ---------------------------------------------------------

fn vbox(spacing: i32) -> gtk::Box {
    gtk::Box::builder().orientation(gtk::Orientation::Vertical).spacing(spacing).build()
}

fn title(t: &str) -> gtk::Label {
    gtk::Label::builder().label(t).xalign(0.0).css_classes(["dfte-title"]).build()
}

fn label(t: &str) -> gtk::Label {
    gtk::Label::builder().label(t).xalign(0.0).css_classes(["dfte-label"]).build()
}

fn caption(t: &str) -> gtk::Label {
    gtk::Label::builder().label(t).xalign(0.0).wrap(true).css_classes(["dfte-caption"]).build()
}

fn pill(t: &str, kind: &str) -> gtk::Button {
    gtk::Button::builder().label(t).css_classes(["dfte-pill", kind]).build()
}

fn chip(t: &str, kind: &str) -> gtk::Label {
    gtk::Label::builder().label(t).valign(gtk::Align::Center).css_classes(["dfte-chip", kind]).build()
}

fn avatar(name: &str) -> gtk::Label {
    gtk::Label::builder().label(text::initials(name)).css_classes(["dfte-avatar"]).build()
}

fn short_fp(fp: &str) -> String {
    fp.split('-').take(4).collect::<Vec<_>>().join("-")
}

/// A card row: label on top, value below (selectable), optional caption.
fn info_row(key: &str, value: &str, hint: Option<&str>) -> gtk::ListBoxRow {
    let b = gtk::Box::builder().spacing(12).css_classes(["dfte-row"]).build();
    let t = vbox(2);
    t.set_hexpand(true);
    t.append(&label(key));
    t.append(&gtk::Label::builder().label(value).xalign(0.0).wrap(true).selectable(true).build());
    if let Some(h) = hint {
        t.append(&caption(h));
    }
    b.append(&t);
    gtk::ListBoxRow::builder().child(&b).activatable(false).build()
}

fn scrolled(child: &impl IsA<gtk::Widget>) -> gtk::Widget {
    let clamp = adw::Clamp::builder().maximum_size(980).child(child).build();
    gtk::ScrolledWindow::builder().child(&clamp).hscrollbar_policy(gtk::PolicyType::Never).vexpand(true).build().upcast()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses_take_a_default_port() {
        assert_eq!(parse_address("192.168.1.20").unwrap(), "192.168.1.20:47821".parse().unwrap());
        assert_eq!(parse_address("10.0.0.2:5000").unwrap(), "10.0.0.2:5000".parse().unwrap());
        assert!(parse_address("phone").is_err());
    }

    #[test]
    fn args_pick_page_and_files() {
        let (p, f) = parse_args(["--page", "receive", "a.bin", "--x", "b c.txt"].into_iter().map(String::from));
        assert_eq!(p, "receive");
        assert_eq!(f, [PathBuf::from("a.bin"), PathBuf::from("b c.txt")]);
        assert_eq!(parse_args(std::iter::empty()), (String::new(), Vec::new()));
    }

    #[test]
    fn actions_follow_direction_and_state() {
        let t = |direction, state| Transfer { id: "x".into(), direction, state, transport: transport::TransportKind::Tcp, bytes_total: 1, bytes_done: 0, resumed_bytes: 0, throughput_bytes_per_sec: 0, peer_fingerprint: None, peer_name: None };
        let names = |t: &Transfer| actions_for(t).into_iter().map(|(n, ..)| n).collect::<Vec<_>>();
        assert_eq!(names(&t(Direction::Send, TransferState::Transferring)), ["Pause", "Cancel"]);
        assert_eq!(names(&t(Direction::Receive, TransferState::Transferring)), ["Cancel"]);
        assert_eq!(names(&t(Direction::Send, TransferState::Paused)), ["Resume"]);
        assert_eq!(names(&t(Direction::Receive, TransferState::Completed)), ["Show in folder"]);
        assert!(names(&t(Direction::Send, TransferState::Completed)).is_empty());
    }
}
