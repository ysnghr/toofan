import requests
import time
from utils.config import settings
from utils.hashing import calculate_file_hash


class VirusTotalAnalyzer:
    """
    Class for integrating VirusTotal API analysis into file analyzers.
    """
    VT_API_KEY = settings.VT_API_KEY

    def analyze_vt_report(self, file_path):
        """
        Extract analysis results from the VirusTotal response.

        Args:
            file_path (str): The path of the file to be analyzed.

        Returns:
            dict: A dictionary with the maliciousness score and list of malicious vendors.
                - 'maliciousness_score' (float): The ratio of malicious detections to total detections.
                - 'malicious_vendors' (list): A list of vendors that flagged the file as malicious.
        """
        vt_response, is_generated = self.get_vt_report(calculate_file_hash(file_path), file_path)
        key = 'last_analysis_results'
        if is_generated:
            key = 'results'
        results = vt_response['data']['attributes'][key]
        total_vendors = len(results)
        malicious_count = sum(1 for result in results.values() if result['category'] == 'malicious')
        malicious_vendors = [name for name, detail in results.items() if detail['category'] == 'malicious']
        return {
            'maliciousness_score': malicious_count / total_vendors,
            'malicious_vendors': malicious_vendors
        }

    def get_vt_report(self, file_hash, file_path):
        """
        Retrieve the report from VirusTotal for a given file hash.

        Args:
            file_hash (str): The MD5 hash of the file.
            file_path (str): The path of the file

        Returns:
            dict: The JSON response from VirusTotal.
        """
        headers = {"X-Apikey": self.VT_API_KEY}
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        response = requests.get(url, headers=headers)
        if response.status_code == 404:
            return self.submit_file(file_path), True
        return response.json(), False

    def submit_file(self, file_path):
        """
        Submit a file to VirusTotal for analysis.

        Args:
            file_path (str): The path to the file.

        Returns:
            dict: The JSON response containing the analysis link.
        """
        headers = {"X-Apikey": self.VT_API_KEY}
        url = "https://www.virustotal.com/api/v3/files"
        with open(file_path, 'rb') as file:
            files = {'file': file}
            response = requests.post(url, headers=headers, files=files)
            analysis_url = response.json()['data']['links']['self']
        return self.poll_vt_analysis(analysis_url)

    def poll_vt_analysis(self, analysis_url):
        """
        Poll the analysis URL until the scan is complete.

        Args:
            analysis_url (str): The URL to poll for results.

        Returns:
            dict: The final analysis results from VirusTotal.
        """
        headers = {"X-Apikey": self.VT_API_KEY}
        max_retries = 3
        retries = 0

        while True:
            try:
                response = requests.get(analysis_url, headers=headers)
                response.raise_for_status()  # Raise an exception for HTTP errors

                if response.json()['data']['attributes']['status'] == 'completed':
                    return response.json()

                time.sleep(10)
            except requests.ConnectionError:
                retries += 1
                if retries >= max_retries:
                    raise Exception
                print("ConnectionError occurred. Retrying...")
                time.sleep(5)
