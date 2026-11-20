"use strict";

const gatewayFileName = "Keenetic-Gateway.zip";
const gatewayForm = $("gatewayForm");
let exportPending = false;

$("openGateway").addEventListener("click", () => {
    back();
    $("connect").hidden = true;
    $("gateway").hidden = false;
    document.querySelector("main").classList.add("gateway-mode");
    $("gatewayIp").focus();
});

$("closeGateway").addEventListener("click", () => {
    gatewayForm.reset();
    back();
    $("openGateway").focus();
});

window.gatewayFileSaved = function (status) {
    exportPending = false;
    if (status === "saved") {
        $("gatewayKey").value = "";
        $("gatewayHWID").value = "";
        message("Архив сохранён. Распакуйте его на шлюзе и откройте README.md.");
    } else if (status === "cancelled") {
        message("Сохранение отменено.");
    } else {
        message("Не удалось сохранить архив. Проверьте доступ к выбранной папке.", true);
    }
};

busy(gatewayForm, "Готовим архив шлюза…", async () => {
    if (exportPending) throw Error("Завершите сохранение предыдущего архива.");
    const {archive} = await send("gateway", {
        LANAddress: $("gatewayIp").value.trim(),
        Port: Number($("gatewayPort").value),
        Subscription: $("gatewayKey").value.trim(),
        UserAgent: $("gatewayUA").value.trim(),
        HWID: $("gatewayHWID").value.trim()
    });
    if (window.ArchiveExport || window.webkit?.messageHandlers?.gatewayArchive) {
        exportPending = true;
        try {
            if (window.ArchiveExport) window.ArchiveExport.save(archive);
            else window.webkit.messageHandlers.gatewayArchive.postMessage(archive);
            message("Выберите, куда сохранить архив шлюза.");
        } catch {
            window.gatewayFileSaved("failed");
        }
        return;
    }
    const bytes = Uint8Array.from(atob(archive), char => char.charCodeAt(0));
    const url = URL.createObjectURL(new Blob([bytes], {type: "application/zip"}));
    const link = document.createElement("a");
    link.href = url;
    link.download = gatewayFileName;
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 30000);
    $("gatewayKey").value = "";
    $("gatewayHWID").value = "";
    message("Архив передан браузеру. После загрузки распакуйте его на шлюзе и откройте README.md.");
});
