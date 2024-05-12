import unittest.mock as mock
import pytest
from analyzers import VirusTotalAnalyzer


class TestVirusTotalAnalyzer:
    @pytest.fixture(autouse=True)
    def setup_analyzer(self):
        self.analyzer = VirusTotalAnalyzer()
        self.analyzer.VT_API_KEY = 'fake_api_key'

    @mock.patch('requests.get')
    def test_get_vt_report_found(self, mock_get):
        mock_response = mock.Mock()
        mock_response.json.return_value = {'data': {'attributes': {'status': 'completed'}}}
        mock_response.status_code = 200
        mock_get.return_value = mock_response

        file_hash = 'dummyhash'
        result = self.analyzer.get_vt_report(file_hash, file_path='dummypath')

        assert result == mock_response.json.return_value
        mock_get.assert_called_once()

    @mock.patch('requests.get')
    def test_get_vt_report_not_found_and_submit_file(self, mock_get):
        mock_response_get_404 = mock.Mock()
        mock_response_get_404.status_code = 404
        mock_response_get_404.json.return_value = {}
        mock_get.return_value = mock_response_get_404

        mock_response_post = mock.Mock()
        mock_response_post.json.return_value = {
            'data': {'links': {'self': 'analysis_url'}}
        }
        with mock.patch('requests.post', return_value=mock_response_post):
            file_hash = 'dummyhash'

            mock_response_get_polling = mock.Mock()
            mock_response_get_polling.json.return_value = {
                'data': {'attributes': {'status': 'completed'}}
            }
            mock_get.side_effect = [mock_response_get_404, mock_response_get_polling]

            file_path = 'tests/resources/pe-files/neolite_arh.exe'
            result = self.analyzer.get_vt_report(file_hash, file_path)

            assert result['data']['attributes']['status'] == 'completed'
            mock_get.assert_has_calls([
                mock.call('https://www.virustotal.com/api/v3/files/dummyhash', headers={'x-apikey': self.analyzer.VT_API_KEY}),
                mock.call('analysis_url', headers={'x-apikey': self.analyzer.VT_API_KEY})
            ])

    @mock.patch('requests.post')
    @mock.patch('requests.get')
    def test_submit_file_and_polling(self, mock_get, mock_post):
        mock_post.return_value = mock.Mock(status_code=200)
        mock_post.return_value.json.return_value = {
            'data': {'links': {'self': 'analysis_url'}}
        }

        mock_get.return_value = mock.Mock(status_code=200)
        mock_get.return_value.json.return_value = {
            'data': {'attributes': {'status': 'completed'}}
        }

        file_path = 'tests/resources/pe-files/neolite_arh.exe'
        result = self.analyzer.submit_file(file_path)

        assert 'data' in result
        mock_post.assert_called_once_with(
            "https://www.virustotal.com/api/v3/files",
            headers={"x-apikey": self.analyzer.VT_API_KEY},
            files={'file': mock.ANY}
        )
        mock_get.assert_called_with('analysis_url', headers={"x-apikey": self.analyzer.VT_API_KEY})
