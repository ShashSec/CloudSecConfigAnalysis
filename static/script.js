document.getElementById('uploadForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const fileInput = document.getElementById('configFile');
    const file = fileInput.files[0];
    if (!file) return;

    const formData = new FormData();
    formData.append('file', file);

    document.getElementById('loading').style.display = 'block';
    document.getElementById('report').style.display = 'none';

    try {
        const response = await fetch('/upload', {
            method: 'POST',
            body: formData
        });
        
        const data = await response.json();
        if (data.error) {
            alert(data.error);
            return;
        }

        displayReport(data.report);
    } catch (error) {
        alert('Error analyzing configuration: ' + error);
    } finally {
        document.getElementById('loading').style.display = 'none';
    }
});

function displayReport(report) {
    const reportDiv = document.getElementById('report');
    const summaryDiv = document.getElementById('summary');
    const findingsDiv = document.getElementById('findings');

    // Display summary
    summaryDiv.innerHTML = `
        <p>Total Resources Analyzed: ${report.total_resources_analyzed}</p>
        <p>Total Findings: ${report.total_findings}</p>
        <p>Failed Analyses: ${report.failed_analyses}</p>
    `;

    // Display findings
    findingsDiv.innerHTML = '';
    Object.entries(report.findings_by_severity).forEach(([severity, findings]) => {
        findings.forEach(finding => {
            const findingDiv = document.createElement('div');
            findingDiv.className = `finding ${severity.toLowerCase()}`;
            findingDiv.innerHTML = `
                <h4>${finding.rule_id}: ${finding.resource_name}</h4>
                <p>${finding.description}</p>
                <p><strong>Recommendation:</strong> ${finding.recommendation}</p>
            `;
            findingsDiv.appendChild(findingDiv);
        });
    });

    reportDiv.style.display = 'block';
}