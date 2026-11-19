document.addEventListener('DOMContentLoaded', () => {
    // Sélection des éléments du formulaire
    const IPV4_REGEX = /^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    const elements = {
        form: document.querySelector('form'),
        scanUnique: document.getElementById('scanUnique'),
        scanReseau: document.getElementById('scanReseau'),
        scanPort: document.getElementById('scanPort'),
        champScanUnique: document.getElementById('champScanUnique'),
        champScanReseau: document.getElementById('champScanReseau'),
        champScanPort: document.getElementById('champScanPort'),
        ipInput: document.getElementById('champIp'),
        portInput: document.getElementById('champPort')
    };

    // Affiche le bon bloc selon le scan sélectionné
    function toggleInputs() {
        elements.champScanUnique.style.display = elements.scanUnique.checked ? 'block' : 'none';
        elements.champScanReseau.style.display = elements.scanReseau.checked ? 'block' : 'none';
        elements.champScanPort.style.display = elements.scanPort.checked ? 'block' : 'none';
        elements.ipInput.required = elements.scanUnique.checked;
        elements.ipInput.disabled = !elements.scanUnique.checked;
        if (elements.portInput) {
            elements.portInput.required = elements.scanPort.checked;
            elements.portInput.disabled = !elements.scanPort.checked;
        }
    }

    // Validation du formulaire avant envoi
    function validateForm(e) {
        if (elements.scanUnique.checked) {
            if (!elements.ipInput.value.match(IPV4_REGEX)) {
                e.preventDefault();
                alert('Veuillez entrer une adresse IPv4 valide');
                elements.ipInput.focus();
                return false;
            }
        }
        if (elements.scanPort.checked) {
            const port = elements.portInput.value;
            if (!port || isNaN(port) || port < 1 || port > 65535) {
                e.preventDefault();
                alert('Veuillez entrer un port valide (1-65535)');
                elements.portInput.focus();
                return false;
            }
        }
        return true;
    }

    // Écouteurs d'événements pour changer l'affichage selon le type de scan choisi
    elements.scanUnique.addEventListener('change', toggleInputs);
    elements.scanReseau.addEventListener('change', toggleInputs);
    elements.scanPort.addEventListener('change', toggleInputs);
    elements.form.addEventListener('submit', validateForm);

    // Initialisation à l'ouverture de la page
    toggleInputs();
});