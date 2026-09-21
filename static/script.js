(() => {
    if (window.__scamEyeInitialized) {
        return;
    }

    window.__scamEyeInitialized = true;

    const messageInput = document.getElementById("messageInput");
    const imageInput = document.getElementById("imageInput");
    const languageSelect = document.getElementById("languageSelect");
    const resultSection = document.getElementById("resultSection");
    const result = document.getElementById("result");
    const loadingState = document.getElementById("loadingState");
    const loadingTitle = document.getElementById("loadingTitle");
    const charCount = document.getElementById("charCount");
    const dropZone = document.getElementById("dropZone");

    const checkButton = document.getElementById("checkButton");
    const clearButton = document.getElementById("clearButton");
    const newScanButton = document.getElementById("newScanButton");
    const browseButton = document.getElementById("browseButton");

    let isAnalyzing = false;
    let isScanningImage = false;

    function escapeHTML(value) {
        return String(value ?? "")
            .replaceAll("&", "&amp;")
            .replaceAll("<", "&lt;")
            .replaceAll(">", "&gt;")
            .replaceAll('"', "&quot;")
            .replaceAll("'", "&#039;");
    }

    function setLoading(active, title = "Analyzing message…") {
    loadingState.hidden = !active;
    loadingState.style.display = active ? "flex" : "none";
    loadingTitle.textContent = title;

    checkButton.disabled = active;
    browseButton.disabled = active;
    clearButton.disabled = active;

    checkButton.classList.toggle("is-loading", active);
}

    function showResultSection() {
        resultSection.hidden = false;
        resultSection.scrollIntoView({
            behavior: "smooth",
            block: "start"
        });
    }

    function showError(message) {
        result.innerHTML = `
            <div class="error-card">
                ${escapeHTML(message)}
            </div>
        `;

        showResultSection();
    }

    function renderList(items) {
        if (!Array.isArray(items) || items.length === 0) {
            return "<li>No strong warning signs were identified.</li>";
        }

        return items
            .map(item => `<li>${escapeHTML(item)}</li>`)
            .join("");
    }

    function renderTranslation(label, text) {
        if (!text) {
            return "";
        }

        return `
            <div class="translation-block">
                <div class="translation-label">
                    ${escapeHTML(label)}
                </div>
                <p>${escapeHTML(text)}</p>
            </div>
        `;
    }

    function renderAnalysis(data) {
        const level = ["High", "Medium", "Low", "Unclear"].includes(
            data.danger_level
        )
            ? data.danger_level
            : "Unclear";

        const translationLanguage = languageSelect.value;

        const translations = translationLanguage
            ? `
                ${renderTranslation(
                    `${translationLanguage} · Explanation`,
                    data.explanation_translation
                )}

                ${renderTranslation(
                    `${translationLanguage} · Safer action`,
                    data.action_translation
                )}
            `
            : "";

        result.innerHTML = `
            <div class="result-main">
                <article class="result-card risk-card risk-${level.toLowerCase()}">
                    <div class="risk-label">OVERALL RISK</div>

                    <div class="risk-level">
                        ${escapeHTML(level)}
                    </div>

                    <div class="risk-type">
                        ${escapeHTML(
                            data.scam_type ||
                            "Insufficient evidence to classify"
                        )}
                    </div>

                    <div class="meta-row">
                        <span class="meta-chip">
                            AI confidence:
                            <b>${escapeHTML(
                                data.confidence || "Low"
                            )}</b>
                        </span>

                        <span class="meta-chip">
                            Signal score:
                            <b>${escapeHTML(
                                data.rule_score ?? "—"
                            )}/100</b>
                        </span>
                    </div>
                </article>

                <article class="result-card">
                    <h3>Warning signs detected</h3>
                    <ul class="warning-list">
                        ${renderList(data.warning_signs)}
                    </ul>
                </article>
            </div>

            <article class="result-card">
                <h3>Why ScamEye flagged it</h3>
                <p>
                    ${escapeHTML(
                        data.explanation ||
                        "No detailed explanation was provided."
                    )}
                </p>

                ${translations}
            </article>

            <article class="result-card action-card">
                <h3>Safer next step</h3>
                <p>
                    ${escapeHTML(
                        data.action ||
                        "Verify the message through an official channel."
                    )}
                </p>

                ${
                    translationLanguage
                        ? renderTranslation(
                            `${translationLanguage} · Next step`,
                            data.action_translation
                        )
                        : ""
                }
            </article>
        `;

        showResultSection();
    }

    async function analyzeMessage() {
        if (isAnalyzing) {
            return;
        }

        const message = messageInput.value.trim();

        if (!message) {
            messageInput.focus();
            showError("Please paste a message first.");
            return;
        }

        isAnalyzing = true;

        setLoading(true, "Analyzing message…");
        resultSection.hidden = true;

        try {
            const response = await fetch("/analyze", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    message,
                    language: languageSelect.value
                })
            });

            const data = await response.json().catch(() => ({}));

            if (!response.ok) {
                throw new Error(
                    data.error ||
                    "The analysis could not be completed."
                );
            }

            renderAnalysis(data);
        } catch (error) {
            console.error("ScamEye analysis error:", error);

            showError(
                error.message ||
                "The analysis service is temporarily unavailable."
            );
        } finally {
            isAnalyzing = false;
            setLoading(false);
        }
    }

    async function scanImage(image) {
        if (isScanningImage) {
            return;
        }

        const allowedTypes = [
            "image/jpeg",
            "image/png",
            "image/webp"
        ];

        if (!allowedTypes.includes(image.type)) {
            showError("Please upload a JPG, PNG, or WebP image.");
            return;
        }

        if (image.size > 6 * 1024 * 1024) {
            showError("Image is too large. Maximum image size is 6 MB.");
            return;
        }

        isScanningImage = true;

        setLoading(true, "Reading screenshot…");
        resultSection.hidden = true;

        const formData = new FormData();
        formData.append("image", image);

        try {
            const response = await fetch("/scan-image", {
                method: "POST",
                body: formData
            });

            const data = await response.json().catch(() => ({}));

            if (!response.ok) {
                throw new Error(
                    data.error ||
                    "Could not read the screenshot."
                );
            }

            messageInput.value = data.extracted_text || "";

            messageInput.dispatchEvent(
                new Event("input", {
                    bubbles: true
                })
            );

            messageInput.focus();
            resultSection.hidden = true;
        } catch (error) {
            console.error("ScamEye image error:", error);

            showError(
                error.message ||
                "Image scanning failed."
            );
        } finally {
            isScanningImage = false;
            setLoading(false);
            imageInput.value = "";
        }
    }

    checkButton.addEventListener("click", event => {
        event.preventDefault();
        event.stopPropagation();
        analyzeMessage();
    });

    clearButton.addEventListener("click", event => {
        event.preventDefault();
        event.stopPropagation();

        if (isAnalyzing || isScanningImage) {
            return;
        }

        messageInput.value = "";
        charCount.textContent = "0 / 8000";
        resultSection.hidden = true;
        result.innerHTML = "";
        messageInput.focus();
    });

    newScanButton.addEventListener("click", event => {
        event.preventDefault();
        event.stopPropagation();

        resultSection.hidden = true;
        result.innerHTML = "";
        messageInput.focus();
    });

    browseButton.addEventListener("click", event => {
        event.preventDefault();
        event.stopPropagation();

        if (isAnalyzing || isScanningImage) {
            return;
        }

        imageInput.click();
    });

    messageInput.addEventListener("input", () => {
        charCount.textContent =
            `${messageInput.value.length} / 8000`;
    });

    document
        .querySelectorAll("[data-example]")
        .forEach(button => {
            button.addEventListener("click", event => {
                event.preventDefault();

                messageInput.value =
                    button.dataset.example || "";

                messageInput.dispatchEvent(
                    new Event("input", {
                        bubbles: true
                    })
                );

                messageInput.focus();
            });
        });

    dropZone.addEventListener("click", event => {
        if (event.target.closest("button")) {
            return;
        }

        if (isAnalyzing || isScanningImage) {
            return;
        }

        imageInput.click();
    });

    ["dragenter", "dragover"].forEach(eventName => {
        dropZone.addEventListener(eventName, event => {
            event.preventDefault();
            event.stopPropagation();

            if (!isAnalyzing && !isScanningImage) {
                dropZone.classList.add("dragover");
            }
        });
    });

    ["dragleave", "drop"].forEach(eventName => {
        dropZone.addEventListener(eventName, event => {
            event.preventDefault();
            event.stopPropagation();
            dropZone.classList.remove("dragover");
        });
    });

    dropZone.addEventListener("drop", event => {
        if (isAnalyzing || isScanningImage) {
            return;
        }

        const file = event.dataTransfer.files?.[0];

        if (file) {
            scanImage(file);
        }
    });

    imageInput.addEventListener("change", event => {
        if (isAnalyzing || isScanningImage) {
            return;
        }

        const file = event.target.files?.[0];

        if (file) {
            scanImage(file);
        }
    });

    messageInput.addEventListener("keydown", event => {
        if (
            (event.ctrlKey || event.metaKey) &&
            event.key === "Enter"
        ) {
            event.preventDefault();
            analyzeMessage();
        }
    });

    messageInput.value = "";
    charCount.textContent = "0 / 8000";
    resultSection.hidden = true;
    loadingState.hidden = true;
})();