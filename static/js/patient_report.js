function initializeHealthChart(dates, weights, bloodPressureSys, bloodPressureDia) {
    const canvas = document.getElementById('healthChart');

    new Chart(canvas, {
        type: 'line',
        data: {
            labels: dates,
            datasets: [
                {
                    label: 'Poids (kg)',
                    data: weights,
                    borderColor: 'rgb(75, 192, 192)',
                    tension: 0.1
                },
                {
                    label: 'Tension artérielle systolique',
                    data: bloodPressureSys,
                    borderColor: 'rgb(255, 99, 132)',
                    tension: 0.1
                },
                {
                    label: 'Tension artérielle diastolique',
                    data: bloodPressureDia,
                    borderColor: 'rgb(54, 162, 235)',
                    tension: 0.1
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: false
                }
            }
        }
    });

}
function sendEmail(email, firstName, lastName) {
    // Récupérer le canvas du graphique
    const canvas = document.getElementById('healthChart');

    // Convertir le canvas en PNG
    const imageData = canvas.toDataURL('image/png');

    // Préparer les headers
    let headers = {
        'Content-Type': 'application/json'
    };

    // Ajouter le token CSRF s'il existe
    const csrfToken = document.querySelector('meta[name="csrf-token"]');
    if (csrfToken) {
        headers['X-CSRFToken'] = csrfToken.content;
    }

    // Désactiver le bouton pendant l'envoi
    const sendButton = event.target;
    sendButton.disabled = true;
    sendButton.textContent = 'Envoi en cours...';

    // Envoyer l'image et les données au serveur
    fetch('/send_report_email', {
        method: 'POST',
        headers: headers,
        body: JSON.stringify({
            email: email,
            firstName: firstName,
            lastName: lastName,
            chartImage: imageData
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            alert(`Le rapport a été envoyé avec succès à ${email}`);
        } else {
            alert(`Erreur lors de l'envoi du rapport: ${data.error}`);
        }
    })
    .catch(error => {
        console.error('Body:', body);
        console.error('Erreur:', error);
        alert('Une erreur est survenue lors de l\'envoi du rapport');
    })
    .finally(() => {
        // Réactiver le bouton après l'envoi
        sendButton.disabled = false;
        sendButton.textContent = 'Envoyer le rapport par mail';
    });
}
