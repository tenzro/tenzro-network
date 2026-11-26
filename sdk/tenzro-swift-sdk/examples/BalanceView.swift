// UNCOMPILED, NEEDS XCODE TO VERIFY.
// Not part of the SwiftPM targets. Written without access to Xcode or an
// Apple SDK; it has not been compiled, run, or rendered. Copy into an app
// target that depends on TenzroSDK.

import SwiftUI
import TenzroSDK

struct BalanceView: View {
    @State private var address = "0x0000000000000000000000000000000000000001"
    @State private var output = ""
    private let client = TenzroClient()

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            TextField("Address", text: $address)
                .textFieldStyle(.roundedBorder)
                .autocorrectionDisabled()
            Button("Query") {
                Task { await query() }
            }
            Text(output).font(.system(.body, design: .monospaced))
        }
        .padding()
    }

    private func query() async {
        do {
            let chain = try await client.getChainId()
            let bal = try await client.getBalance(address)
            output = "chain \(chain)\nbalance (raw units) \(bal.decimal)"
        } catch {
            output = "error: \(error.localizedDescription)"
        }
    }
}
