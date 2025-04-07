// DOM property constants
const textContentProp = "textContent";
const innerHTMLProp = "innerHTML";
const buttonClass = " buttonQuestionblock"; // Leading space intentional
const brTag = "<br>";
const lastChildProp = "lastChild";
const firstChildProp = "firstChild";
const parentElementProp = "parentElement";
const classListProp = "classList";
const targetProp = "target";
const containsMethod = "contains";
const appendChildMethod = "appendChild";
const styleProp = "style";
const displayProp = "display";

// Custom Enneagram knowledge (Modify this as needed)
const enneagramKnowledge = `
  Oscar Ichazo’s Enneagram describes nine personality types, each based on core fears and motivations:
  - Type 1: The Perfectionist – Seeks integrity, avoids mistakes.
  - Type 2: The Helper – Seeks love, avoids rejection.
  - Type 3: The Achiever – Seeks success, avoids failure.
  - Type 4: The Individualist – Seeks authenticity, avoids being ordinary.
  - Type 5: The Investigator – Seeks knowledge, avoids depletion.
  - Type 6: The Loyalist – Seeks security, avoids uncertainty.
  - Type 7: The Enthusiast – Seeks excitement, avoids pain.
  - Type 8: The Challenger – Seeks control, avoids weakness.
  - Type 9: The Peacemaker – Seeks harmony, avoids conflict.
  Always answer within this context without explicitly mentioning 'Enneagram' unless asked directly.
  `;

// Helper functions
const createElement = (tagName) => document.createElement(tagName);

const createButton = (className, text) => {
  const button = createElement("button");
  button.className = className;
  button[textContentProp] = text;
  return button;
};

// AI API interaction function with proper context injection
const fetchAndDisplayResponse = async (questionElement, responseContainer) => {
  responseContainer[textContentProp] = "AI is thinking...";

  const promptText = `
    ${enneagramKnowledge}
    ---
    User Question: "${questionElement[textContentProp]}"
    Explain this based on the provided context with detailed examples.
    `;

  try {
    const response = await fetch(
      "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash-latest:generateContent?key=YOUR_GEMINI_API_KEY",
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          contents: [{ parts: [{ text: promptText }] }],
        }),
      },
    );

    const data = await response.json();
    const responseText =
      data.candidates?.[0]?.content?.parts?.[0]?.text ||
      "No response received.";

    // Format the response
    responseContainer[innerHTMLProp] =
      `<i>"${questionElement[textContentProp]}"</i>${brTag}${brTag}` +
      responseText.replace(/\n/g, brTag).replace(/\*\*(.*?)\*\*/g, "<b>$1</b>");
  } catch (error) {
    console.error("Error fetching response:", error);
    responseContainer[textContentProp] = "Error retrieving AI response.";
  }
};

// Initialize question blocks
const initializeQuestionBlocks = (selector) => {
  document.querySelectorAll(selector).forEach((container) => {
    const overlay = createElement("div");
    const responseBox = createElement("div");
    const questionButton = createButton("_m" + buttonClass, "?");

    // Create control buttons
    const closeButton = createButton("_c" + buttonClass, "Close");
    const retryButton = createButton("_r" + buttonClass, "Retry");

    // Style overlay
    overlay[styleProp] =
      "display:none;flex-direction:column;align-items:center;" +
      "justify-content:center;position:fixed;top:0;left:0;width:100vw;" +
      "height:100vh;z-index:9999;background:rgba(0,0,0,.5);backdrop-filter:blur(4px);";

    // Style response box
    responseBox[styleProp] =
      "text-align:left;overflow-y:auto;width:75%;height:60%;";

    // Build overlay structure
    overlay.appendChild(responseBox);
    overlay.appendChild(closeButton);
    overlay.appendChild(retryButton);

    // Add elements to container
    container.appendChild(questionButton);
    container.appendChild(overlay);
  });
};

// Initialize components
initializeQuestionBlocks(".question1");
initializeQuestionBlocks(".question2");

// Event listeners
document.body.addEventListener("click", async (event) => {
  const target = event[targetProp];

  // Handle question button click
  if (target[classListProp][containsMethod]("_m")) {
    const overlay = target[parentElementProp][lastChildProp];
    const responseBox = overlay[firstChildProp];

    overlay[styleProp][displayProp] = "flex";

    if (!responseBox[textContentProp]) {
      const questionElement = target[parentElementProp].querySelector(".en");
      await fetchAndDisplayResponse(questionElement, responseBox);
    }
  }

  // Handle close button click
  if (target[classListProp][containsMethod]("_c")) {
    target[parentElementProp][styleProp][displayProp] = "none";
  }

  // Handle retry button click
  if (target[classListProp][containsMethod]("_r")) {
    const responseBox = target[parentElementProp][firstChildProp];
    const questionElement =
      target[parentElementProp][parentElementProp].querySelector(".en");
    await fetchAndDisplayResponse(questionElement, responseBox);
  }
});
