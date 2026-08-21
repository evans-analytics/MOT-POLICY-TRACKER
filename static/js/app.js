(() => {
    const search = document.querySelector('#global-search');
    if (!search) return;
    const palette = document.querySelector('#command-palette');
    const commandInput = document.querySelector('#command-input');
    const commandResults = document.querySelector('#command-results');

    const closePalette = () => palette.classList.remove('open');
    const renderResults = (results) => {
        commandResults.innerHTML = results.length
            ? results.map((result) => `<a class="command-result" href="${result.url}"><span><strong>${result.label}</strong><br><small>${result.detail}</small></span><span class="command-type">${result.type}</span></a>`).join('')
            : '<div class="command-result"><span>No matching records</span></div>';
    };

    const searchWorkspace = async (value) => {
        if (value.trim().length < 2) {
            commandResults.innerHTML = '<div class="command-result"><span>Type at least 2 characters</span></div>';
            return;
        }
        const response = await fetch(`/global-search?q=${encodeURIComponent(value.trim())}`);
        if (response.ok) renderResults((await response.json()).results);
    };

    document.addEventListener('keydown', (event) => {
        if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') {
            event.preventDefault();
            palette.classList.add('open');
            commandInput.focus();
        }
        if (event.key === 'Escape') closePalette();
    });

    palette.addEventListener('click', (event) => {
        if (event.target === palette) closePalette();
    });

    commandInput.addEventListener('input', () => searchWorkspace(commandInput.value));
    commandInput.addEventListener('keydown', (event) => {
        if (event.key === 'Enter' && commandInput.value.trim()) {
            search.value = commandInput.value;
            window.location.href = `/?search_query=${encodeURIComponent(commandInput.value.trim())}`;
        }
    });
})();
