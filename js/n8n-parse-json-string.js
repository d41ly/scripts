//parse json array returned as string, made for n8n
for (let item of items) {
  if (typeof item.json.body.entries === 'string') {
    try {
      item.json.body.entries = JSON.parse(item.json.body.entries);
    } catch (e) {
      console.error('Error parsing entries:', e);
    }
  }
}

return items;