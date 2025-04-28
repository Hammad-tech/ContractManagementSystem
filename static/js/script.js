// Construction Claims Management Application JavaScript

document.addEventListener('DOMContentLoaded', function() {
    // Initialize Bootstrap tooltips
    const tooltips = document.querySelectorAll('[data-bs-toggle="tooltip"]');
    if (tooltips.length > 0) {
        [...tooltips].map(tooltip => new bootstrap.Tooltip(tooltip));
    }
    
    // Initialize Bootstrap popovers
    const popovers = document.querySelectorAll('[data-bs-toggle="popover"]');
    if (popovers.length > 0) {
        [...popovers].map(popover => new bootstrap.Popover(popover));
    }
    
    // Auto-scroll chat container to bottom
    const chatContainer = document.querySelector('.chat-container');
    if (chatContainer) {
        chatContainer.scrollTop = chatContainer.scrollHeight;
    }
    
    // File input customization
    const fileInputs = document.querySelectorAll('.custom-file-input');
    fileInputs.forEach(input => {
        input.addEventListener('change', function(e) {
            const fileName = this.files[0]?.name || 'No file chosen';
            const nextSibling = this.nextElementSibling;
            if (nextSibling) {
                nextSibling.innerText = fileName;
            }
        });
    });
    
    // Confirm deletion of project
    const deleteProjectButtons = document.querySelectorAll('.delete-project-btn');
    deleteProjectButtons.forEach(button => {
        button.addEventListener('click', function(e) {
            if (!confirm('Are you sure you want to delete this project? This action cannot be undone.')) {
                e.preventDefault();
            }
        });
    });
    
    // Report page: initialize any charts if Chart.js is available
    if (typeof Chart !== 'undefined' && document.getElementById('riskCategoryChart')) {
        initializeRiskChart();
    }
    
    // Animate elements when they come into view
    if ('IntersectionObserver' in window) {
        const fadeElements = document.querySelectorAll('.fade-in-element');
        
        const fadeInObserver = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    entry.target.classList.add('fade-in');
                    fadeInObserver.unobserve(entry.target);
                }
            });
        }, { threshold: 0.1 });
        
        fadeElements.forEach(element => {
            fadeInObserver.observe(element);
        });
    }
});

// Function to initialize risk category chart on report page
function initializeRiskChart() {
    // This would use data attributes or a data element in the HTML to get risk data
    // For this example, we'll assume the data is in data attributes
    const ctx = document.getElementById('riskCategoryChart').getContext('2d');
    const riskLabels = JSON.parse(document.getElementById('riskCategoryChart').dataset.labels || '[]');
    const riskCounts = JSON.parse(document.getElementById('riskCategoryChart').dataset.counts || '[]');
    
    if (riskLabels.length > 0 && riskCounts.length > 0) {
        new Chart(ctx, {
            type: 'bar',
            data: {
                labels: riskLabels,
                datasets: [{
                    label: 'Risk Categories',
                    data: riskCounts,
                    backgroundColor: [
                        'rgba(255, 99, 132, 0.5)',
                        'rgba(54, 162, 235, 0.5)',
                        'rgba(255, 206, 86, 0.5)',
                        'rgba(75, 192, 192, 0.5)',
                        'rgba(153, 102, 255, 0.5)',
                        'rgba(255, 159, 64, 0.5)',
                        'rgba(199, 199, 199, 0.5)',
                        'rgba(83, 102, 255, 0.5)',
                        'rgba(40, 159, 64, 0.5)'
                    ],
                    borderColor: [
                        'rgba(255, 99, 132, 1)',
                        'rgba(54, 162, 235, 1)',
                        'rgba(255, 206, 86, 1)',
                        'rgba(75, 192, 192, 1)',
                        'rgba(153, 102, 255, 1)',
                        'rgba(255, 159, 64, 1)',
                        'rgba(199, 199, 199, 1)',
                        'rgba(83, 102, 255, 1)',
                        'rgba(40, 159, 64, 1)'
                    ],
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: {
                            precision: 0
                        }
                    }
                }
            }
        });
    }
}
