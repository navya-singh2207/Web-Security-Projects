(function () {
    const output = document.getElementById("dom-output");
    if (!output) return;

    const level = document.body.dataset.level || "low";

    function getPayload() {
        const hash = window.location.hash ? window.location.hash.slice(1) : "";
        if (hash) {
            return decodeURIComponent(hash);
        }
        const params = new URLSearchParams(window.location.search);
        return params.get("msg") || "";
    }

    function enforceTrustedTypes() {
        if (window.trustedTypes && !window.trustedTypes.getPolicy("domLabPolicy")) {
            window.trustedTypes.createPolicy("domLabPolicy", {
                createHTML: (input) => input,
            });
        }
    }

    function render() {
        const payload = getPayload() || "Waiting for hash payload...";
        if (level === "low") {
            output.innerHTML = payload;
        } else {
            enforceTrustedTypes();
            output.textContent = payload;
        }
    }

    window.addEventListener("hashchange", render);
    window.addEventListener("load", render);
})();
