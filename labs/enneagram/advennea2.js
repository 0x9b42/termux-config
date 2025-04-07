const textContentProp = "textContent";
const innerHTMLProp = "innerHTML";
const buttonClass = " buttonQuestionblock";
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

let knowledgeBase = [];
const MAX_TOKENS = 4000; // Safe token limit for Gemini 1.5 Flash

// Load knowledge from JSON file
const loadKnowledgeBase = async () => {
  try {
    const response = await fetch("enneagram_knowledge.json");
    knowledgeBase = await response.json();
  } catch (error) {
    console.error("Error loading knowledge base:", error);
  }
};

// Estimate token count (roughly 1 token ≈ 4 chars)
const countTokens = (text) => Math.ceil(text.length / 4);

// Chunk long text into manageable pieces
const chunkText = (text, maxTokens) => {
  let tokens = countTokens(text);
  if (tokens <= maxTokens) return [text]; // No need to split

  let chunks = [];
  let sentences = text.split(". "); // Split by sentences
  let currentChunk = "";

  for (let sentence of sentences) {
    if (countTokens(currentChunk + sentence) > maxTokens) {
      chunks.push(currentChunk);
      currentChunk = "";
    }
    currentChunk += sentence + ". ";
  }
  if (currentChunk) chunks.push(currentChunk); // Add last chunk

  return chunks;
};

// Retrieve the most relevant content, chunking if necessary
const getRelevantKnowledge = (query) => {
  query = query.toLowerCase();
  let bestMatch = knowledgeBase.find(
    (article) =>
      article.title.toLowerCase().includes(query) ||
      article.content.toLowerCase().includes(query),
  );

  if (!bestMatch) return "No relevant information found.";

  let chunks = chunkText(bestMatch.content, MAX_TOKENS / 2); // Keep half the limit
  return `Relevant Information:\n${bestMatch.title}\n${chunks[0]}`;
};

const createElement = (tagName) => document.createElement(tagName);

const createButton = (className, text) => {
  const button = createElement("button");
  button.className = className;
  button[textContentProp] = text;
  return button;
};

const fetchAndDisplayResponse = async (questionElement, responseContainer) => {
  responseContainer[textContentProp] = "AI is thinking...";

  const userQuery = questionElement[textContentProp];
  const relevantKnowledge = getRelevantKnowledge(userQuery);

  const promptText = `
    ${relevantKnowledge}
    ---
    User Question: "${userQuery}"
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

    responseContainer[innerHTMLProp] =
      `<i>"${userQuery}"</i>${brTag}${brTag}` +
      responseText.replace(/\n/g, brTag).replace(/\*\*(.*?)\*\*/g, "<b>$1</b>");
  } catch (error) {
    console.error("Error fetching response:", error);
    responseContainer[textContentProp] = "Error retrieving AI response.";
  }
};

const initializeQuestionBlocks = (selector) => {
  document.querySelectorAll(selector).forEach((container) => {
    const overlay = createElement("div");
    const responseBox = createElement("div");
    const questionButton = createButton("_m" + buttonClass, "?");

    const closeButton = createButton("_c" + buttonClass, "Close");
    const retryButton = createButton("_r" + buttonClass, "Retry");

    overlay[styleProp] =
      "display:none;flex-direction:column;align-items:center;" +
      "justify-content:center;position:fixed;top:0;left:0;width:100vw;" +
      "height:100vh;z-index:9999;background:rgba(0,0,0,.5);backdrop-filter:blur(4px);";

    responseBox[styleProp] =
      "text-align:left;overflow-y:auto;width:75%;height:60%;";

    overlay.appendChild(responseBox);
    overlay.appendChild(closeButton);
    overlay.appendChild(retryButton);

    container.appendChild(questionButton);
    container.appendChild(overlay);
  });
};

initializeQuestionBlocks(".question1");
initializeQuestionBlocks(".question2");

document.body.addEventListener("click", async (event) => {
  const target = event[targetProp];

  if (target[classListProp][containsMethod]("_m")) {
    const overlay = target[parentElementProp][lastChildProp];
    const responseBox = overlay[firstChildProp];

    overlay[styleProp][displayProp] = "flex";

    if (!responseBox[textContentProp]) {
      const questionElement = target[parentElementProp].querySelector(".en");
      await fetchAndDisplayResponse(questionElement, responseBox);
    }
  }

  if (target[classListProp][containsMethod]("_c")) {
    target[parentElementProp][styleProp][displayProp] = "none";
  }

  if (target[classListProp][containsMethod]("_r")) {
    const responseBox = target[parentElementProp][firstChildProp];
    const questionElement =
      target[parentElementProp][parentElementProp].querySelector(".en");
    await fetchAndDisplayResponse(questionElement, responseBox);
  }
});

loadKnowledgeBase(); // Load knowledge on startup
