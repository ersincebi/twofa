import AppKit
import ServiceManagement
import SwiftUI
import UniformTypeIdentifiers

// MARK: - Root

private enum Screen: Equatable {
    case list
    case form(Account?)
    case connect
}

struct RootView: View {
    @EnvironmentObject private var store: AccountStore
    @State private var screen: Screen = .list

    var body: some View {
        Group {
            switch screen {
            case .list:
                AccountListView(
                    onAdd: { screen = .form(nil) },
                    onEdit: { screen = .form($0) },
                    onConnect: { screen = .connect }
                )
            case .form(let account):
                AccountFormView(existing: account) { screen = .list }
            case .connect:
                ConnectView { screen = .list }
            }
        }
        .frame(width: 320)
        .onAppear { Task { await store.sync() } }
    }
}

// MARK: - List

struct AccountListView: View {
    @EnvironmentObject private var store: AccountStore
    @State private var search = ""

    let onAdd: () -> Void
    let onEdit: (Account) -> Void
    let onConnect: () -> Void

    private var filtered: [Account] {
        guard !search.isEmpty else { return store.accounts }
        return store.accounts.filter {
            $0.issuer.localizedCaseInsensitiveContains(search)
                || $0.name.localizedCaseInsensitiveContains(search)
        }
    }

    var body: some View {
        VStack(spacing: 0) {
            if store.accounts.count > 4 {
                TextField("Search", text: $search)
                    .textFieldStyle(.roundedBorder)
                    .padding([.horizontal, .top], 10)
            }

            if let loadError = store.loadError {
                Text(loadError)
                    .font(.caption)
                    .foregroundStyle(.red)
                    .padding(12)
            } else if store.accounts.isEmpty {
                EmptyStateView(onAdd: onAdd)
            } else {
                ScrollView {
                    TimelineView(.periodic(from: .now, by: 1)) { context in
                        LazyVStack(spacing: 4) {
                            ForEach(filtered) { account in
                                AccountRow(account: account, date: context.date) {
                                    onEdit(account)
                                }
                            }
                        }
                        .padding(8)
                    }
                }
                .frame(maxHeight: 440)
                .fixedSize(horizontal: false, vertical: true)
            }

            if case .failed(let message) = store.syncStatus {
                Text(message)
                    .font(.caption)
                    .foregroundStyle(.orange)
                    .padding(.horizontal, 12)
                    .padding(.bottom, 6)
            }

            Divider()
            FooterView(onAdd: onAdd, onConnect: onConnect)
        }
    }
}

private struct EmptyStateView: View {
    let onAdd: () -> Void

    var body: some View {
        VStack(spacing: 10) {
            Image(systemName: "lock.shield")
                .font(.system(size: 32))
                .foregroundStyle(.secondary)
            Text("No accounts yet")
                .font(.headline)
            Button("Add Account", action: onAdd)
                .buttonStyle(.borderedProminent)
        }
        .frame(maxWidth: .infinity)
        .padding(24)
    }
}

// MARK: - Row

struct AccountRow: View {
    @EnvironmentObject private var store: AccountStore
    @State private var isHovering = false
    @State private var showCopied = false

    let account: Account
    let date: Date
    let onEdit: () -> Void

    private var code: String { account.code(at: date) }
    private var remaining: Int { TOTP.secondsRemaining(period: account.period, date: date) }

    var body: some View {
        HStack(spacing: 10) {
            VStack(alignment: .leading, spacing: 2) {
                Text(account.displayTitle)
                    .font(.subheadline.weight(.semibold))
                    .lineLimit(1)
                if !account.name.isEmpty && !account.issuer.isEmpty {
                    Text(account.name)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                }
                Text(showCopied ? "Copied!" : formatted(code))
                    .font(.system(size: 22, weight: .medium, design: .monospaced))
                    .foregroundStyle(showCopied ? Color.green : (remaining <= 5 ? Color.red : Color.primary))
            }

            Spacer(minLength: 0)

            if isHovering {
                RowActions(account: account, onEdit: onEdit)
            }
            CountdownRing(remaining: remaining, period: account.period)
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 6)
        .background(
            RoundedRectangle(cornerRadius: 8)
                .fill(isHovering ? Color.primary.opacity(0.08) : Color.clear)
        )
        .contentShape(Rectangle())
        .onHover { isHovering = $0 }
        .onTapGesture(perform: copy)
        .contextMenu {
            Button("Copy Code", action: copy)
            Button("Edit…", action: onEdit)
            Divider()
            Button("Delete", role: .destructive) { store.delete(account) }
        }
        .help("Click to copy")
    }

    private func formatted(_ code: String) -> String {
        let mid = code.index(code.startIndex, offsetBy: code.count / 2)
        return "\(code[..<mid]) \(code[mid...])"
    }

    private func copy() {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(code, forType: .string)
        withAnimation { showCopied = true }
        DispatchQueue.main.asyncAfter(deadline: .now() + 1) {
            withAnimation { showCopied = false }
        }
    }
}

private struct RowActions: View {
    @EnvironmentObject private var store: AccountStore
    @State private var confirmDelete = false

    let account: Account
    let onEdit: () -> Void

    var body: some View {
        HStack(spacing: 2) {
            if confirmDelete {
                Button("Delete") { store.delete(account) }
                    .buttonStyle(.borderedProminent)
                    .tint(.red)
                    .controlSize(.small)
                Button { confirmDelete = false } label: { Image(systemName: "xmark") }
                    .buttonStyle(.borderless)
            } else {
                Button { store.move(account, by: -1) } label: { Image(systemName: "chevron.up") }
                    .help("Move up")
                Button { store.move(account, by: 1) } label: { Image(systemName: "chevron.down") }
                    .help("Move down")
                Button(action: onEdit) { Image(systemName: "pencil") }
                    .help("Edit")
                Button { confirmDelete = true } label: { Image(systemName: "trash") }
                    .help("Delete")
            }
        }
        .buttonStyle(.borderless)
        .foregroundStyle(.secondary)
    }
}

private struct CountdownRing: View {
    let remaining: Int
    let period: Int

    var body: some View {
        ZStack {
            Circle()
                .stroke(Color.secondary.opacity(0.25), lineWidth: 3)
            Circle()
                .trim(from: 0, to: CGFloat(remaining) / CGFloat(period))
                .stroke(remaining <= 5 ? Color.red : Color.accentColor,
                        style: StrokeStyle(lineWidth: 3, lineCap: .round))
                .rotationEffect(.degrees(-90))
                .animation(.linear(duration: 1), value: remaining)
            Text("\(remaining)")
                .font(.system(size: 10, weight: .medium, design: .monospaced))
                .foregroundStyle(.secondary)
        }
        .frame(width: 28, height: 28)
    }
}

// MARK: - Footer

private struct FooterView: View {
    @EnvironmentObject private var store: AccountStore
    @State private var launchAtLogin = SMAppService.mainApp.status == .enabled

    let onAdd: () -> Void
    let onConnect: () -> Void

    var body: some View {
        HStack {
            Button(action: onAdd) {
                Label("Add", systemImage: "plus")
            }
            SyncIndicator(status: store.syncStatus)
            Spacer()
            Toggle("Launch at login", isOn: $launchAtLogin)
                .toggleStyle(.checkbox)
                .font(.caption)
                .onChange(of: launchAtLogin, perform: setLaunchAtLogin)
            Spacer()
            Menu {
                Button("Export Backup…") { Backup.export(store.accounts) }
                    .disabled(store.accounts.isEmpty)
                Button("Import Backup…") { Backup.importFile(into: store) }
                Divider()
                if store.isSyncEnabled {
                    Button("Sync Now") { Task { await store.sync() } }
                    Button("Disconnect Sync") { store.disconnect() }
                } else {
                    Button("Connect to Sync…", action: onConnect)
                }
            } label: {
                Image(systemName: "ellipsis.circle")
            }
            .menuStyle(.borderlessButton)
            .menuIndicator(.hidden)
            .fixedSize()
            .disabled(store.loadError != nil)
            Button("Quit") { NSApp.terminate(nil) }
                .keyboardShortcut("q")
        }
        .buttonStyle(.borderless)
        .padding(10)
    }

    private func setLaunchAtLogin(_ enabled: Bool) {
        do {
            if enabled {
                try SMAppService.mainApp.register()
            } else {
                try SMAppService.mainApp.unregister()
            }
        } catch {
            NSLog("TwoFA: launch at login failed: \(error)")
            launchAtLogin = SMAppService.mainApp.status == .enabled
        }
    }
}

private struct SyncIndicator: View {
    let status: SyncStatus

    var body: some View {
        switch status {
        case .off:
            EmptyView()
        case .syncing:
            ProgressView().controlSize(.mini)
        case .synced:
            icon("checkmark.icloud", .green, "Synced with 2fa.ersincebi.com")
        case .offline:
            icon("icloud.slash", .orange, "Offline — showing the saved copy")
        case .failed(let message):
            icon("exclamationmark.icloud", .red, message)
        }
    }

    private func icon(_ name: String, _ color: Color, _ help: String) -> some View {
        Image(systemName: name)
            .foregroundStyle(color)
            .help(help)
    }
}

// MARK: - Connect to sync

struct ConnectView: View {
    @EnvironmentObject private var store: AccountStore
    @State private var password = ""
    @State private var error: String?
    @State private var working = false

    let onDone: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Connect to Sync")
                .font(.headline)
            Text("Use the master password of your vault at 2fa.ersincebi.com. Accounts on this Mac are added to it.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            SecureField("Master password", text: $password)
                .textFieldStyle(.roundedBorder)
                .onSubmit(connect)
                .disabled(working)

            if let error {
                Text(error)
                    .font(.caption)
                    .foregroundStyle(.red)
            }

            HStack {
                if working {
                    ProgressView().controlSize(.small)
                }
                Spacer()
                Button("Cancel", action: onDone)
                    .keyboardShortcut(.cancelAction)
                Button("Connect", action: connect)
                    .keyboardShortcut(.defaultAction)
                    .buttonStyle(.borderedProminent)
                    .disabled(password.isEmpty || working)
            }
        }
        .padding(14)
    }

    private func connect() {
        guard !password.isEmpty, !working else { return }
        working = true
        error = nil
        Task {
            do {
                try await store.connect(password: password)
                onDone()
            } catch {
                self.error = error.localizedDescription
            }
            working = false
        }
    }
}

// MARK: - Add / Edit form

struct AccountFormView: View {
    @EnvironmentObject private var store: AccountStore
    @State private var draft: Account
    @State private var error: String?

    private let isNew: Bool
    let onDone: () -> Void

    init(existing: Account?, onDone: @escaping () -> Void) {
        _draft = State(initialValue: existing ?? Account(issuer: "", name: "", secret: ""))
        isNew = existing == nil
        self.onDone = onDone
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(isNew ? "Add Account" : "Edit Account")
                .font(.headline)

            Form {
                TextField("Issuer", text: $draft.issuer, prompt: Text("GitHub"))
                TextField("Account", text: $draft.name, prompt: Text("me@example.com"))
                HStack {
                    TextField("Secret", text: $draft.secret, prompt: Text("Base32 key or otpauth:// link"))
                        .font(.system(.body, design: .monospaced))
                        .onSubmit(save)
                    Button("Paste", action: pasteSecret)
                        .help("Paste a secret, an otpauth:// link or a QR code screenshot")
                    Button(action: openQRImage) { Image(systemName: "qrcode.viewfinder") }
                        .help("Open a QR code image")
                }
                Picker("Digits", selection: $draft.digits) {
                    ForEach(6...8, id: \.self) { Text("\($0)").tag($0) }
                }
                Picker("Period", selection: $draft.period) {
                    ForEach([15, 30, 60], id: \.self) { Text("\($0)s").tag($0) }
                }
                Picker("Algorithm", selection: $draft.algorithm) {
                    ForEach(OTPAlgorithm.allCases) { Text($0.rawValue).tag($0) }
                }
            }
            .onChange(of: draft.secret) { _ in
                error = nil
                importURIIfNeeded()
            }

            if let error {
                Text(error)
                    .font(.caption)
                    .foregroundStyle(.red)
            }

            HStack {
                if !isNew {
                    Button("Delete", role: .destructive) {
                        store.delete(draft)
                        onDone()
                    }
                }
                Spacer()
                Button("Cancel", action: onDone)
                    .keyboardShortcut(.cancelAction)
                Button("Save", action: save)
                    .keyboardShortcut(.defaultAction)
                    .buttonStyle(.borderedProminent)
            }
        }
        .padding(14)
    }

    private func pasteSecret() {
        if let image = NSImage(pasteboard: NSPasteboard.general) {
            useQRCode(in: image)
        } else if let text = NSPasteboard.general.string(forType: .string) {
            draft.secret = text.trimmingCharacters(in: .whitespacesAndNewlines)
        }
    }

    private func openQRImage() {
        let panel = NSOpenPanel()
        panel.allowedContentTypes = [.image]
        NSApp.activate(ignoringOtherApps: true)
        guard panel.runModal() == .OK, let url = panel.url, let image = NSImage(contentsOf: url) else { return }
        useQRCode(in: image)
    }

    private func useQRCode(in image: NSImage) {
        guard let link = QRCode.messages(in: image).first(where: { $0.lowercased().hasPrefix("otpauth://totp") }) else {
            error = "No TOTP QR code found in the image."
            return
        }
        draft.secret = link
    }

    /// If an otpauth:// link was pasted, fill the whole form from it.
    private func importURIIfNeeded() {
        guard draft.secret.lowercased().hasPrefix("otpauth://"),
              let parsed = Account(otpauthURI: draft.secret)
        else { return }
        let id = draft.id
        draft = parsed
        draft.id = id
    }

    private func save() {
        draft.issuer = draft.issuer.trimmingCharacters(in: .whitespaces)
        draft.name = draft.name.trimmingCharacters(in: .whitespaces)
        draft.secret = Base32.normalize(draft.secret)

        guard Base32.decode(draft.secret) != nil else {
            error = "Secret must be a valid Base32 key (A–Z, 2–7)."
            return
        }
        guard !draft.issuer.isEmpty || !draft.name.isEmpty else {
            error = "Enter an issuer or account name."
            return
        }
        store.upsert(draft)
        onDone()
    }
}
