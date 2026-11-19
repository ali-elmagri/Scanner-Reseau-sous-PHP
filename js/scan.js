// Bouton de copie IP/OS : copie l'IP et l'OS dans le presse-papier et affiche une icône de confirmation
document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('.copy-btn').forEach(btn => {
        btn.addEventListener('click', function() {
            const ip = this.dataset.ip;
            const os = this.dataset.os;
            const text = `IP: ${ip}\nOS: ${os}`;
            navigator.clipboard.writeText(text).then(() => {
                this.innerHTML = '<i class="bi bi-clipboard-check"></i>';
                setTimeout(() => {
                    this.innerHTML = '<i class="bi bi-clipboard"></i>';
                }, 2000);
            });
        });
    });
});