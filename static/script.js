document.getElementById('uploadForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const fileInput = document.getElementById('configFile');
    const apiKeyInput = document.getElementById('openaiKey');
    const file = fileInput.files[0];
    if (!file) return;

    const formData = new FormData();
    formData.append('file', file);
    if (apiKeyInput.value) {
        formData.append('openai_api_key', apiKeyInput.value);
    }

    document.getElementById('loading').style.display = 'block';
    document.getElementById('report').style.display = 'none';
    clearResults();
    
    try {
        const response = await fetch('/analyze', {
            method: 'POST',
            body: formData
        });

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const data = await response.json();
        if (data.error) {
            throw new Error(data.error);
        }

        // Display rule-based findings immediately
        if (data.report.rule_based_findings) {
            displayRuleFindings(data.report.rule_based_findings);
        }

        // Display AI-based findings if available
        if (data.report.ai_based_findings && data.report.ai_based_findings.total > 0) {
            displayAIFindings(data.report.ai_based_findings);
        }

        document.getElementById('loading').style.display = 'none';
        document.getElementById('report').style.display = 'block';

    } catch (error) {
        console.error('Error:', error);
        document.getElementById('loading').style.display = 'none';
        alert('Error during analysis: ' + error.message);
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

function displayRuleFindings(findings) {
    const ruleSection = document.getElementById('ruleFindings');
    ruleSection.innerHTML = '';
    
    if (findings.total === 0) {
        ruleSection.innerHTML = '<p>No rule-based findings</p>';
        return;
    }
    
    findings.findings.forEach(finding => {
        const findingDiv = document.createElement('div');
        findingDiv.className = `finding ${finding.severity}`;
        findingDiv.innerHTML = `
            <h4>${finding.rule_id}: ${finding.resource_name}</h4>
            <p>${finding.description}</p>
            <p><strong>Recommendation:</strong> ${finding.recommendation}</p>
        `;
        ruleSection.appendChild(findingDiv);
    });
}

function displayAIFindings(findings) {
    const aiSection = document.getElementById('aiFindings');
    aiSection.innerHTML = '';
    
    if (findings.total === 0) {
        aiSection.innerHTML = '<p>No AI-based findings</p>';
        return;
    }
    
    findings.findings.forEach(finding => {
        const findingDiv = document.createElement('div');
        findingDiv.className = `finding ${finding.severity}`;
        findingDiv.innerHTML = `
            <h4>${finding.rule_id}: ${finding.resource_name}</h4>
            <p>${finding.description}</p>
            <p><strong>Recommendation:</strong> ${finding.recommendation}</p>
        `;
        aiSection.appendChild(findingDiv);
    });
}

function clearResults() {
    document.getElementById('ruleFindings').innerHTML = '';
    document.getElementById('aiFindings').innerHTML = '';
}