import json
import asyncio
import logging
from pathlib import Path
from typing import List, Dict
from datetime import datetime
from dataclasses import asdict
from openai import AsyncOpenAI
from pathlib import Path
import asyncio
import json

from models.resource import Resource
from registry.rule_registry import SecurityRuleRegistry
from registry.rule_loader import RuleLoader
from engine.analysis_engine import SecurityAnalysisEngine
from models.ai_findings import AIFindings, AIFinding

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class SecurityAnalyzer:
    def __init__(self, resources_file: str, openai_api_key: str = None):
        self.resources_file = Path(resources_file)
        self.registry = SecurityRuleRegistry()
        self.loader = RuleLoader(self.registry)
        self.engine = SecurityAnalysisEngine(self.registry)
        self.openai_api_key = openai_api_key
        # Initialize OpenAI client once during initialization if API key provided
        self.openai_client = AsyncOpenAI(api_key=openai_api_key) if openai_api_key else None

    def load_resources(self) -> List[Resource]:
        """Load resources from JSON file and convert to Resource objects"""
        try:
            with open(self.resources_file, 'r') as f:
                data = json.load(f)
                resources_list = data.get('resources', [])
                
            # Convert each dictionary to Resource object
            resources = []
            for item in resources_list:
                if self._validate_resource_json(item):
                    resource = Resource(
                        name=item.get('name'),
                        type=item.get('type'),
                        properties=item
                    )
                    resources.append(resource)
                else:
                    logging.warning(f"Skipping invalid resource: {item.get('name', 'unknown')}")
            
            logging.info(f"Loaded {len(resources)} resources")
            return resources
        except Exception as e:
            logging.error(f"Error loading resources: {str(e)}")
            raise        
        except FileNotFoundError:
            logger.error(f"Resources file not found: {self.resources_file}")
            raise
        except json.JSONDecodeError:
            logger.error(f"Invalid JSON in resources file: {self.resources_file}")
            raise
        except KeyError as e:
            logger.error(f"Missing required field in resources file: {e}")
            raise

    def _validate_resource_json(self, item: Dict) -> bool:
        """Validate that the JSON has the minimum required fields."""
        required_fields = ['type', 'name']
        return all(field in item for field in required_fields)
    
    async def get_openai_analysis(self, resource: Dict, resource_type: str, cis_doc: str) -> List[Dict]:
        if not self.openai_client:
            logger.warning("OpenAI analysis skipped - no API key provided")
            return []
        
        try:
            # Truncate CIS doc to reduce token count
            max_cis_length = 2000
            truncated_cis = cis_doc[:max_cis_length] if cis_doc else ""
        
            # Simplify resource JSON to essential fields
            simplified_resource = {
                "name": resource.get("name"),
                "type": resource.get("type"),
                "azure_specific": resource.get("azure_specific", {})
            }

            prompt = f"""
            As a cloud security expert, analyze this {resource_type} resource and return findings in this exact JSON format:
            [{{
                "rule_id": "AI_{resource_type}_001",
                "resource_name": "{simplified_resource['name']}",
                "resource_type": "{resource_type}",
                "severity": "HIGH",
                "description": "Brief security issue description",
                "recommendation": "Brief recommendation"
            }}]

            Resource configuration:
            {json.dumps(simplified_resource, indent=2)}
            
            CIS guidelines:
            {truncated_cis}
            
            Return ONLY the JSON array with findings. Each finding MUST have all required fields.
            """

            max_retries = 3
            retry_delay = 1
        
            for attempt in range(max_retries):
                try:
                    response = await self.openai_client.chat.completions.create(
                        model="gpt-4-turbo-preview",
                        messages=[
                            {"role": "system", "content": "You are a cloud security expert. Respond only with valid JSON arrays."},
                            {"role": "user", "content": prompt}
                        ],
                        temperature=0,
                        response_format={"type": "json_object"},
                        max_tokens=4000
                    )

                    content = response.choices[0].message.content
                    findings = json.loads(content)
                    
                    # Ensure we have a list of findings
                    if isinstance(findings, dict):
                        findings = [findings]
                    
                    # Convert each finding to AIFinding object then back to dict
                    ai_findings = []
                    for finding in findings:
                        ai_finding = AIFinding.from_dict(finding)
                        ai_findings.append(vars(ai_finding))
                        
                    return ai_findings
                
                except Exception as e:
                    if attempt == max_retries - 1:
                        raise
                    await asyncio.sleep(retry_delay * (2 ** attempt))
                
        except Exception as e:
            logger.error(f"OpenAI API call failed for {resource.get('name')}: {e}")
            return []

    def _get_cis_doc(self, resource_type: str) -> str:
        try:
            cis_path = Path(f"cis_benchmark/{resource_type}.md")
            if cis_path.exists():
                return cis_path.read_text(encoding='utf-8', errors='ignore')
        except Exception as e:
            logger.warning(f"Could not load CIS doc for {resource_type}: {e}")
        return ""

    async def analyze_resources(self) -> Dict:
        try:
            logger.info("Loading security rules...")
            self.loader.load_all_rules()
            
            logger.info("Loading resources from file...")
            resources = self.load_resources()

            # Get existing rule types from directories
            rule_types = {d.name for d in Path("rules").iterdir() 
                         if d.is_dir() and not d.name.startswith('__')}
            logger.info(f"Available rule types: {rule_types}")

            all_findings = []
            ai_findings = []
            failed_resources = []

            # Process resources with rules first
            for resource in resources:
                if resource.type in rule_types:
                    try:
                        logger.info(f"Analyzing resource with rules: {resource.name} ({resource.type})")
                        findings = await self.engine.analyze_resource(resource)
                        all_findings.extend(findings)
                    except Exception as e:
                        logger.error(f"Rule analysis failed for {resource.name}: {e}")
                        failed_resources.append({
                            'name': resource.name,
                            'type': resource.type,
                            'error': str(e)
                        })

            # Process resources without rules using OpenAI
            if self.openai_api_key:
                for resource in resources:
                    if resource.type not in rule_types:
                        try:
                            logger.info(f"Processing with OpenAI: {resource.name} ({resource.type})")
                            findings = await self.get_openai_analysis(
                                resource.properties,
                                resource.type,
                                self._get_cis_doc(resource.type)
                            )
                            if findings:
                                ai_findings.extend(findings)
                        except Exception as e:
                            logger.error(f"OpenAI analysis failed for {resource.name}: {e}")
                            # Don't add to failed_resources as this is supplementary analysis

            # Generate report
            report = {
                'timestamp': datetime.now().isoformat(),
                'total_resources_analyzed': len(resources),
                'successful_analyses': len(resources) - len(failed_resources),
                'failed_analyses': len(failed_resources),
                'failed_resources': failed_resources,
                'rule_based_findings': {
                    'total': len(all_findings),
                    'findings': [asdict(f) for f in all_findings]
                },
                'ai_based_findings': {
                    'total': len(ai_findings),
                    'findings': ai_findings
                }
            }
            
            return report

        except Exception as e:
            logger.error(f"Error during analysis: {e}")
            raise
        
    def _group_findings_by_severity(self, findings):
        """Group findings by severity level."""
        severity_groups = {'HIGH': [], 'MEDIUM': [], 'LOW': []}
        for finding in findings:
            severity_groups[finding.severity].append(asdict(finding))
        return severity_groups

    def _group_findings_by_resource(self, findings):
        """Group findings by resource type."""
        resource_groups = {}
        for finding in findings:
            if finding.resource_type not in resource_groups:
                resource_groups[finding.resource_type] = []
            resource_groups[finding.resource_type].append(asdict(finding))
        return resource_groups

    def save_report(self, report: Dict, output_file: str):
        """Save the analysis report to a JSON file."""
        try:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_path, 'w') as f:
                json.dump(report, f, indent=2)
            
            logger.info(f"Report saved to: {output_path}")
            
        except Exception as e:
            logger.error(f"Error saving report: {e}")
            raise

async def main():
    try:
        # Initialize the analyzer
        analyzer = SecurityAnalyzer('data/resources.json')
        
        # Run the analysis
        report = await analyzer.analyze_resources()
        
        # Save the report
        analyzer.save_report(report, 'output/security_report.json')
        
        # Print summary
        print("\nAnalysis Summary:")
        print(f"Total resources analyzed: {report['total_resources_analyzed']}")
        print(f"Total findings: {report['total_findings']}")
        print("\nFindings by Severity:")
        for severity, findings in report['findings_by_severity'].items():
            print(f"{severity}: {len(findings)} findings")
            
    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        raise

if __name__ == "__main__":
    asyncio.run(main())