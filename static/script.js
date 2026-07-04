const imageInput = document.getElementById("imageInput");

document.getElementById("checkButton").onclick = async function () {
    const message = document.getElementById("messageInput").value;
    const result = document.getElementById("result");
    const language = document.getElementById("languageSelect").value;

    if (message.trim() === "") {
        result.textContent = "Please paste a message first.";
        return;
    }

    result.textContent = "Checking message...";

    try {
        const response = await fetch("/analyze", {
            method: "POST",

            headers: {
                "Content-Type": "application/json"
            },

            body: JSON.stringify({
                message: message,
                language: language
            })
        });

        if (!response.ok) {
            throw new Error("Server error");
        }

        const data = await response.json();

        let riskTitle;

        if (data.danger_level === "High") {
            riskTitle = "🚨 HIGH RISK!";
        } else if (data.danger_level === "Medium") {
            riskTitle = "⚠️ MEDIUM RISK";
        } else if (data.danger_level === "Low") {
            riskTitle = "✅ LOW RISK";
        } else {
            riskTitle = "❓ UNCLEAR";
        }

        const translation = language ? `
            <p>
                <strong>Type:</strong> ${data.scam_type}<br>
                <span class="translation">
                    (${data.scam_type_translation})
                </span>
            </p>

            <p>
                <strong>Why:</strong> ${data.explanation}<br>
                <span class="translation">
                    (${data.explanation_translation})
                </span>
            </p>

            <p>
                <strong>What to do:</strong> ${data.action}<br>
                <span class="translation">
                    (${data.action_translation})
                </span>
            </p>
        ` : `
            <p>
                <strong>Type:</strong> ${data.scam_type}
            </p>

            <p>
                <strong>Why:</strong> ${data.explanation}
            </p>

            <p>
                <strong>What to do:</strong> ${data.action}
            </p>
        `;

        result.innerHTML = `
            <h2>${riskTitle}</h2>
            ${translation}
        `;

    } catch (error) {
        console.error(error);

        result.textContent =
            "The AI service is temporarily busy. Please try again.";
    }
};


imageInput.onchange = async function () {
    const image = imageInput.files[0];
    const messageInput = document.getElementById("messageInput");
    const result = document.getElementById("result");

    if (!image) {
        return;
    }

    result.textContent = "Scanning image...";

    const formData = new FormData();
    formData.append("image", image);

    try {
        const response = await fetch("/scan-image", {
            method: "POST",
            body: formData
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(
                data.error || "Could not scan the image."
            );
        }

        messageInput.value = data.extracted_text;

        result.textContent =
            "Image scanned! Check the extracted text, then press Check Message.";

    } catch (error) {
        console.error(error);

        result.textContent =
            "Image scanning failed: " + error.message;
    }
};