import SwiftUI

@main
struct TwoFAApp: App {
    @StateObject private var store = AccountStore()

    var body: some Scene {
        MenuBarExtra("TwoFA", systemImage: "lock.shield") {
            RootView()
                .environmentObject(store)
        }
        .menuBarExtraStyle(.window)
    }
}
