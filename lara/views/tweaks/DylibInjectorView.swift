//
//  DylibInjectorView.swift
//  lara
//

import SwiftUI
import UniformTypeIdentifiers

// Processo vivo (via proclist kernel)
private struct LiveProcess: Identifiable, Hashable {
    let id = UUID()
    let pid: Int32
    let name: String
    let kaddr: UInt64
}

struct DylibInjectorView: View {
    @ObservedObject private var mgr = laramgr.shared

    @State private var liveProcs: [LiveProcess] = []
    @State private var query: String = ""
    @State private var selectedProc: LiveProcess? = nil

    @State private var stagedDylib: URL? = nil
    @State private var showFilePicker: Bool = false

    @State private var isInjecting: Bool = false
    @State private var alertTitle: String = ""
    @State private var alertBody: String = ""
    @State private var showAlert: Bool = false
    @State private var injectionSucceeded: Bool = false

    private var filtered: [LiveProcess] {
        let q = query.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        return q.isEmpty ? liveProcs : liveProcs.filter { $0.name.lowercased().contains(q) }
    }

    private var canInject: Bool {
        mgr.dsready && selectedProc != nil && stagedDylib != nil && !isInjecting
    }

    var body: some View {
        List {
            // Status banner
            if !mgr.dsready {
                Section {
                    Text("Kernel R/W não está pronto. Execute o exploit primeiro.")
                        .foregroundColor(.secondary)
                } header: { Text("Status") }
            }

            // ── Step 1: Processo alvo ──────────────────────────────────
            Section {
                HStack {
                    TextField("Buscar processo…", text: $query)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    Spacer()
                    Button { loadLiveProcs() } label: {
                        Image(systemName: "arrow.clockwise")
                    }
                    .disabled(!mgr.dsready)
                }

                if liveProcs.isEmpty && mgr.dsready {
                    Text("Nenhum processo carregado. Toque em ↺.")
                        .foregroundColor(.secondary)
                        .font(.subheadline)
                } else {
                    ForEach(filtered) { p in
                        Button {
                            selectedProc = p
                        } label: {
                            HStack {
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(p.name)
                                        .font(.headline)
                                        .foregroundColor(.primary)
                                    Text("PID \(p.pid)")
                                        .font(.caption)
                                        .foregroundColor(.secondary)
                                        .monospaced()
                                }
                                Spacer()
                                if selectedProc?.pid == p.pid {
                                    Image(systemName: "checkmark.circle.fill")
                                        .foregroundColor(.accentColor)
                                }
                            }
                        }
                    }
                }
            } header: {
                Text("Passo 1 — Processo Alvo")
            } footer: {
                if let s = selectedProc {
                    Text("Selecionado: \(s.name) (PID \(s.pid))")
                        .foregroundColor(.accentColor)
                } else {
                    Text("Toque em um processo para selecionar o alvo da injeção.")
                }
            }

            // ── Step 2: Dylib ──────────────────────────────────────────
            Section {
                Button {
                    showFilePicker = true
                } label: {
                    Label(
                        stagedDylib == nil
                            ? "Selecionar .dylib…"
                            : (stagedDylib!.lastPathComponent),
                        systemImage: "doc.badge.plus"
                    )
                }
                .disabled(selectedProc == nil)

                if let dylib = stagedDylib {
                    HStack(alignment: .top) {
                        Text("Caminho:")
                            .foregroundColor(.secondary)
                        Spacer()
                        Text(dylib.path)
                            .font(.caption)
                            .foregroundColor(.secondary)
                            .monospaced()
                            .lineLimit(3)
                            .truncationMode(.head)
                            .multilineTextAlignment(.trailing)
                    }
                }
            } header: {
                Text("Passo 2 — Dylib")
            } footer: {
                Text("A dylib será carregada no processo alvo via dlopen(path, RTLD_NOW | RTLD_GLOBAL).")
            }

            // ── Step 3: Injetar ────────────────────────────────────────
            Section {
                Button {
                    inject()
                } label: {
                    HStack {
                        if isInjecting {
                            ProgressView().padding(.trailing, 6)
                        }
                        Text(isInjecting ? "Injetando…" : "Injetar")
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                }
                .disabled(!canInject)
            } header: {
                Text("Passo 3 — Injetar")
            } footer: {
                Text("Cria uma sessão RemoteCall com o processo alvo e executa dlopen remotamente.")
            }
        }
        .navigationTitle("Dylib Injector")
        .fileImporter(
            isPresented: $showFilePicker,
            allowedContentTypes: [.item],
            allowsMultipleSelection: false
        ) { result in
            if case .success(let urls) = result, let url = urls.first {
                stageDylib(url)
            }
        }
        .alert(alertTitle, isPresented: $showAlert) {
            if injectionSucceeded, selectedProc?.name == "SpringBoard" {
                Button("Respring") { mgr.respring() }
            }
            Button("OK", role: .cancel) {}
        } message: {
            Text(alertBody)
        }
        .onAppear {
            if mgr.dsready && liveProcs.isEmpty { loadLiveProcs() }
        }
    }

    // MARK: – Carregar processos vivos

    private func loadLiveProcs() {
        guard mgr.dsready else { return }
        DispatchQueue.global(qos: .userInitiated).async {
            var count: Int32 = 0
            guard let raw = proclist(nil, &count), count > 0 else {
                DispatchQueue.main.async { liveProcs = [] }
                return
            }
            defer { free_proclist(raw) }

            var out: [LiveProcess] = []
            for i in 0..<Int(count) {
                let e = raw[i]
                let name = withUnsafePointer(to: e.name) { ptr in
                    ptr.withMemoryRebound(to: CChar.self, capacity: 32) {
                        String(cString: $0)
                    }
                }
                guard !name.isEmpty else { continue }
                out.append(LiveProcess(pid: Int32(e.pid), name: name, kaddr: e.kaddr))
            }
            out.sort { $0.name.lowercased() < $1.name.lowercased() }
            DispatchQueue.main.async { liveProcs = out }
        }
    }

    // MARK: – Staging da dylib

    private func stageDylib(_ url: URL) {
        let fm = FileManager.default
        let dir = fm.urls(for: .documentDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("Dylibs")
        try? fm.createDirectory(at: dir, withIntermediateDirectories: true)
        let dst = dir.appendingPathComponent(url.lastPathComponent)

        _ = url.startAccessingSecurityScopedResource()
        defer { url.stopAccessingSecurityScopedResource() }

        do {
            if fm.fileExists(atPath: dst.path) { try fm.removeItem(at: dst) }
            try fm.copyItem(at: url, to: dst)
            DispatchQueue.main.async { self.stagedDylib = dst }
        } catch {
            DispatchQueue.main.async {
                alertTitle  = "Erro ao copiar dylib"
                alertBody   = error.localizedDescription
                showAlert   = true
                injectionSucceeded = false
            }
        }
    }

    // MARK: – Injeção

    private func inject() {
        guard let target = selectedProc, let dylib = stagedDylib else { return }
        guard mgr.dsready else { return }

        isInjecting = true
        let procName  = target.name
        let dylibPath = dylib.path
        mgr.logmsg("(inject) alvo='\(procName)' pid=\(target.pid) dylib='\(dylib.lastPathComponent)'")

        DispatchQueue.global(qos: .userInitiated).async {
            // Cria RemoteCall dedicado para o processo alvo (não usa sbProc)
            guard let rc = RemoteCall(process: procName, useMigFilterBypass: false) else {
                let err = RemoteCall.lastInitError() ?? "erro desconhecido"
                DispatchQueue.main.async {
                    mgr.logmsg("(inject) RC init falhou para '\(procName)': \(err)")
                    alertTitle = "Falha na conexão"
                    alertBody  = "Não foi possível conectar ao processo '\(procName)'.\n\nErro: \(err)"
                    injectionSucceeded = false
                    showAlert  = true
                    isInjecting = false
                }
                return
            }

            let ret = dylibPath.withCString { cPath in
                inject_dylib(rc, cPath)
            }
            rc.destroyRemoteCall()

            DispatchQueue.main.async {
                isInjecting = false
                if ret == 0 {
                    mgr.logmsg("(inject) '\(dylib.lastPathComponent)' -> '\(procName)' OK")
                    alertTitle = "Injeção concluída"
                    alertBody  = "'\(dylib.lastPathComponent)' carregada em '\(procName)' com sucesso."
                    if procName == "SpringBoard" {
                        alertBody += "\n\nRespring recomendado para aplicar as mudanças."
                    }
                    injectionSucceeded = true
                } else {
                    mgr.logmsg("(inject) '\(dylib.lastPathComponent)' -> '\(procName)' FALHOU errno=\(ret)")
                    alertTitle = "Injeção falhou"
                    alertBody  = "dlopen falhou no processo '\(procName)' (errno \(ret)).\n\nVerifique se o processo está em execução e se a dylib é acessível ao processo alvo."
                    injectionSucceeded = false
                }
                showAlert = true
            }
        }
    }       // ← fecha inject()
}           // ← fecha DylibInjectorView
