chrome.action.onClicked.addListener(async (tab) => {
  await chrome.scripting.insertCSS({ target: { tabId: tab.id }, files: ["panel.css"] });
  await chrome.scripting.executeScript({ target: { tabId: tab.id }, files: ["content.js"] });
});
