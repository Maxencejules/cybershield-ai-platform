document.addEventListener('DOMContentLoaded', () => {
    const token = localStorage.getItem('token');
    if (!token && window.location.pathname !== '/login') {
        window.location.href = '/login';
        return;
    }

    if (window.location.pathname === '/') {
        loadDashboardData();
    }

    document.getElementById('logoutBtn')?.addEventListener('click', () => {
        localStorage.removeItem('token');
        window.location.href = '/login';
    });
});

async function loadDashboardData() {
    try {
        const response = await fetch('/api/dashboard', {
            headers: {
                'Authorization': `Bearer ${localStorage.getItem('token')}`
            }
        });
        const result = await response.json();

        if (result.success) {
            updateDashboard(result.data);
        }
    } catch (error) {
        console.error('Error loading dashboard:', error);
    }
}

function updateDashboard(data) {
    document.getElementById('total-events').innerText = data.overview.total_events;
    document.getElementById('threats-detected').innerText = data.overview.threats_detected;
    document.getElementById('system-health').innerText = data.overview.system_health;
    document.getElementById('active-alerts').innerText = data.overview.threats_detected; // Simplified

    // Update Activity List
    const activityList = document.getElementById('recent-activity-list');
    activityList.innerHTML = '';
    data.recent_activity.forEach(activity => {
        const li = document.createElement('li');
        li.className = 'list-group-item d-flex justify-content-between align-items-center';
        li.innerHTML = `
            <span>${activity.message}</span>
            <span class="badge bg-${getBadgeColor(activity.severity)} rounded-pill">${activity.severity}</span>
        `;
        activityList.appendChild(li);
    });

    // Update Chart
    const ctx = document.getElementById('threatChart').getContext('2d');
    new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: Object.keys(data.threat_distribution),
            datasets: [{
                data: Object.values(data.threat_distribution),
                backgroundColor: ['#dc3545', '#fd7e14', '#ffc107', '#28a745', '#17a2b8']
            }]
        }
    });
}

function getBadgeColor(severity) {
    switch(severity) {
        case 'critical': return 'danger';
        case 'high': return 'warning';
        case 'medium': return 'info';
        default: return 'secondary';
    }
}
