import SwiftUI
import WebKit

@main
struct RouterSetupApp: App {
    init() {
        _ = GatewayExportFiles.directory
    }

    var body: some Scene {
        WindowGroup { SetupPage() }
    }
}

private enum GatewayExportFiles {
    // Swift initializes this once per process, before any window creates an export.
    static let directory: URL = {
        let files = FileManager.default
        let folder = files.temporaryDirectory.appendingPathComponent("RouterSetup-GatewayExports", isDirectory: true)
        try? files.removeItem(at: folder)
        return folder
    }()
}

struct SetupPage: UIViewControllerRepresentable {
    func makeUIViewController(context: Context) -> WizardController { WizardController() }
    func updateUIViewController(_ controller: WizardController, context: Context) {}
}

private final class GatewayExportHandler: NSObject, WKScriptMessageHandler {
    weak var owner: WizardController?
    func userContentController(_ controller: WKUserContentController, didReceive message: WKScriptMessage) {
        owner?.exportGateway(message)
    }
}

final class WizardController: UIViewController, WKNavigationDelegate, UIDocumentPickerDelegate {
    private var originPort: Int?
    private var browser: WKWebView?
    private let status = UILabel()
    private let retry = UIButton(type: .system)
    private var attempt = 0
    private var exportDirectory: URL?

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .systemBackground
        status.font = .preferredFont(forTextStyle: .body)
        status.numberOfLines = 0
        status.textAlignment = .center
        retry.setTitle("Попробовать снова", for: .normal)
        retry.addTarget(self, action: #selector(start), for: .touchUpInside)
        let stack = UIStackView(arrangedSubviews: [status, retry])
        stack.axis = .vertical
        stack.spacing = 12
        stack.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.centerYAnchor.constraint(equalTo: view.centerYAnchor),
            stack.leadingAnchor.constraint(equalTo: view.safeAreaLayoutGuide.leadingAnchor, constant: 24),
            stack.trailingAnchor.constraint(equalTo: view.safeAreaLayoutGuide.trailingAnchor, constant: -24)
        ])
        NotificationCenter.default.addObserver(self, selector: #selector(stopEngine),
            name: UIApplication.willTerminateNotification, object: nil)
        start()
    }

    @objc private func stopEngine() { KSetupStop() }

    private func local(_ url: URL?) -> Bool {
        guard let url = url, let port = originPort else { return false }
        return url.scheme == "http" && url.host == "127.0.0.1" && url.port == port
            && url.user == nil && url.password == nil
    }

    @objc private func start() {
        attempt += 1
        let startingAttempt = attempt
        browser?.removeFromSuperview()
        browser = nil
        retry.isHidden = true
        status.text = "Открываем настройку роутера…"
        guard let raw = KSetupStart(), let url = URL(string: raw),
              let port = url.port, (1...65535).contains(port) else { fail(); return }
        originPort = port
        guard local(url), url.path == "/", url.query == nil, !(url.fragment ?? "").isEmpty else {
            fail(); return
        }

        // Filters also apply to subresources, where navigation delegate checks do not run.
        let rules: [[String: Any]] = [
            ["trigger": ["url-filter": ".*"], "action": ["type": "block"]],
            ["trigger": ["url-filter": "^http://127[.]0[.]0[.]1:\(port)/"],
             "action": ["type": "ignore-previous-rules"]]
        ]
        guard let data = try? JSONSerialization.data(withJSONObject: rules),
              let json = String(data: data, encoding: .utf8) else { fail(); return }
        WKContentRuleListStore.default().compileContentRuleList(forIdentifier: "PrivateRouterOrigin",
                encodedContentRuleList: json) { [weak self] list, _ in
            guard let self = self, self.attempt == startingAttempt else { return }
            guard let list = list else { self.fail(); return }
            let config = WKWebViewConfiguration()
            config.websiteDataStore = .nonPersistent()
            config.userContentController.add(list)
            let exporter = GatewayExportHandler()
            exporter.owner = self
            config.userContentController.add(exporter, name: "gatewayArchive")
            config.defaultWebpagePreferences.allowsContentJavaScript = true
            let page = WKWebView(frame: .zero, configuration: config)
            page.navigationDelegate = self
            page.translatesAutoresizingMaskIntoConstraints = false
            self.view.addSubview(page)
            let safe = self.view.safeAreaLayoutGuide
            NSLayoutConstraint.activate([
                page.leadingAnchor.constraint(equalTo: safe.leadingAnchor),
                page.trailingAnchor.constraint(equalTo: safe.trailingAnchor),
                page.topAnchor.constraint(equalTo: safe.topAnchor),
                page.bottomAnchor.constraint(equalTo: safe.bottomAnchor)
            ])
            self.browser = page
            page.load(URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData,
                timeoutInterval: 12))
        }
    }

    fileprivate func exportGateway(_ message: WKScriptMessage) {
        guard message.webView === browser, message.frameInfo.isMainFrame,
              local(message.frameInfo.request.url), exportDirectory == nil else { return }
        guard let encoded = message.body as? String, encoded.utf8.count <= 6 * 1024 * 1024,
              let bytes = Data(base64Encoded: encoded) else { finishExport("failed"); return }
        let folder = GatewayExportFiles.directory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        exportDirectory = folder
        do {
            try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
            let file = folder.appendingPathComponent("Keenetic-Gateway.zip")
            try bytes.write(to: file, options: [.atomic, .completeFileProtection])
            let picker = UIDocumentPickerViewController(forExporting: [file], asCopy: true)
            picker.delegate = self
            present(picker, animated: true)
        } catch { finishExport("failed") }
    }

    private func finishExport(_ result: String) {
        if let folder = exportDirectory { try? FileManager.default.removeItem(at: folder) }
        exportDirectory = nil
        browser?.evaluateJavaScript("window.gatewayFileSaved('\(result)')", completionHandler: nil)
    }

    func documentPicker(_ controller: UIDocumentPickerViewController, didPickDocumentsAt urls: [URL]) {
        finishExport(urls.isEmpty ? "failed" : "saved")
    }

    func documentPickerWasCancelled(_ controller: UIDocumentPickerViewController) {
        finishExport("cancelled")
    }

    private func fail() {
        originPort = nil
        browser?.removeFromSuperview()
        browser = nil
        KSetupStop()
        status.text = "Не удалось открыть локальный интерфейс настройки."
        retry.isHidden = false
    }

    func webView(_ webView: WKWebView, decidePolicyFor navigationAction: WKNavigationAction,
                 decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
        let allowed = navigationAction.targetFrame != nil && local(navigationAction.request.url)
        decisionHandler(allowed ? .allow : .cancel)
    }

    func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!,
                 withError error: Error) {
        guard webView === browser, (error as NSError).code != NSURLErrorCancelled else { return }
        fail()
    }

    func webViewWebContentProcessDidTerminate(_ webView: WKWebView) {
        if webView === browser { fail() }
    }
}
