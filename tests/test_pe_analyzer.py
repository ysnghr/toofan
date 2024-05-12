"""
This module contains tests for the PEAnalyzer class.
"""
import pytest
from file_management.file_manager import FileManager
from analyzers.pe_analyzer import PEAnalyzer
from unittest.mock import patch


class TestPEAnalyzer:
    """Test class for the PEAnalyzer."""

    @pytest.fixture
    def file_manager(self):
        """Fixture for creating a FileManager instance."""
        return FileManager()

    @pytest.mark.parametrize("file_path, expected_results", [('aspack_Autoruns.exe', {'Packing status': 'Packed',
                                                                                      'Packers': [
                                                                                          'ASPackv212AlexeySolodovnikov',
                                                                                          'ASProtectV2XDLLAlexeySolodovnikov',
                                                                                          '.ASPack', '.adata'],
                                                                                      'Architecture': 'x86',
                                                                                      'Called DLLs': ['kernel32.dll',
                                                                                                      'version.dll',
                                                                                                      'comctl32.dll',
                                                                                                      'crypt32.dll',
                                                                                                      'wintrust.dll',
                                                                                                      'ntdll.dll',
                                                                                                      'user32.dll',
                                                                                                      'gdi32.dll',
                                                                                                      'comdlg32.dll',
                                                                                                      'advapi32.dll',
                                                                                                      'shell32.dll',
                                                                                                      'ole32.dll',
                                                                                                      'oleaut32.dll',
                                                                                                      'shlwapi.dll',
                                                                                                      'winhttp.dll'],
                                                                                      'IP addresses': [],
                                                                                      'Domain names': [], 'URLs': []}),
                                                             ('bero_Autoruns.exe', {'Packing status': 'Packed',
                                                                                    'Packers': ['BeRoEXEPackerV100BeRo'],
                                                                                    'Architecture': 'x86',
                                                                                    'Called DLLs': ['kernel32.dll'],
                                                                                    'IP addresses': [],
                                                                                    'Domain names': [], 'URLs': []}), (
                                                             'enigmavb_Autoruns.exe',
                                                             {'Packing status': 'Packed', 'Packers': ['Borland'],
                                                              'Architecture': 'x86',
                                                              'Called DLLs': ['kernel32.dll', 'user32.dll',
                                                                              'advapi32.dll', 'oleaut32.dll',
                                                                              'kernel32.dll', 'advapi32.dll',
                                                                              'kernel32.dll', 'user32.dll',
                                                                              'kernel32.dll', 'kernel32.dll',
                                                                              'ole32.dll', 'oleaut32.dll',
                                                                              'oleaut32.dll', 'ntdll.dll',
                                                                              'SHFolder.dll', 'ntdll.dll',
                                                                              'shlwapi.dll', 'ntdll.dll'],
                                                              'IP addresses': [], 'Domain names': [], 'URLs': []}), (
                                                             'fsg_Autoruns.exe', {'Packing status': 'Packed',
                                                                                  'Packers': ['FSGv10', 'FSGv100Engdulekxt',
                                                                                              'FSGv110Engdulekxt'],
                                                                                  'Architecture': 'x86',
                                                                                  'Called DLLs': ['KERNEL32.dll'],
                                                                                  'IP addresses': [],
                                                                                  'Domain names': [], 'URLs': []}), (
                                                             'mew_Autoruns.exe',
                                                             {'Packing status': 'Packed', 'Packers': ['mew_11_xx'],
                                                              'Architecture': 'x86', 'Called DLLs': ['kernel32.dll'],
                                                              'IP addresses': [], 'Domain names': [], 'URLs': []}), (
                                                             'molebox_Autoruns.exe', {'Packing status': 'Packed',
                                                                                      'Packers': ['MoleBoxv20',
                                                                                                  'MoleBoxV23XMoleStudiocom'],
                                                                                      'Architecture': 'x86',
                                                                                      'Called DLLs': ['KERNEL32.dll',
                                                                                                      'USER32.dll'],
                                                                                      'IP addresses': [],
                                                                                      'Domain names': [], 'URLs': []}),
                                                             ('mpress_Autoruns.exe', {'Packing status': 'Packed',
                                                                                      'Packers': ['mpress_2_xx_x86',
                                                                                                  '.MPRESS1',
                                                                                                  '.MPRESS2'],
                                                                                      'Architecture': 'x86',
                                                                                      'Called DLLs': ['KERNEL32.DLL',
                                                                                                      'VERSION.dll',
                                                                                                      'COMCTL32.dll',
                                                                                                      'CRYPT32.dll',
                                                                                                      'WINTRUST.dll',
                                                                                                      'ntdll.dll',
                                                                                                      'USER32.dll',
                                                                                                      'GDI32.dll',
                                                                                                      'COMDLG32.dll',
                                                                                                      'ADVAPI32.dll',
                                                                                                      'SHELL32.dll',
                                                                                                      'ole32.dll',
                                                                                                      'OLEAUT32.dll',
                                                                                                      'SHLWAPI.dll',
                                                                                                      'WINHTTP.dll'],
                                                                                      'IP addresses': [],
                                                                                      'Domain names': [], 'URLs': []}),
                                                             ('neolite_arh.exe', {'Packing status': 'Packed',
                                                                                  'Packers': ['NeoLitev20', '.neolit'],
                                                                                  'Architecture': 'x86',
                                                                                  'Called DLLs': ['KERNEL32.dll',
                                                                                                  'VERSION.dll',
                                                                                                  'msi.dll',
                                                                                                  'SHLWAPI.dll',
                                                                                                  'ADVAPI32.dll'],
                                                                                  'IP addresses': [],
                                                                                  'Domain names': [], 'URLs': []}), (
                                                             'nspack_Autoruns.exe', {'Packing status': 'Packed',
                                                                                     'Packers': ['nSpackV2xLiuXingPing',
                                                                                                 'NsPackV2XLiuXingPing',
                                                                                                 'NsPackv23NorthStar',
                                                                                                 'nsp0', 'nsp1'],
                                                                                     'Architecture': 'x86',
                                                                                     'Called DLLs': ['KERNEL32.DLL',
                                                                                                     'VERSION.DLL',
                                                                                                     'COMCTL32.DLL',
                                                                                                     'CRYPT32.DLL',
                                                                                                     'WINTRUST.DLL',
                                                                                                     'NTDLL.DLL',
                                                                                                     'USER32.DLL',
                                                                                                     'GDI32.DLL',
                                                                                                     'COMDLG32.DLL',
                                                                                                     'ADVAPI32.DLL',
                                                                                                     'SHELL32.DLL',
                                                                                                     'OLE32.DLL',
                                                                                                     'OLEAUT32.DLL',
                                                                                                     'SHLWAPI.DLL',
                                                                                                     'WINHTTP.DLL'],
                                                                                     'IP addresses': [],
                                                                                     'Domain names': [], 'URLs': []}), (
                                                             'packman_Autoruns.exe', {'Packing status': 'Packed',
                                                                                      'Packers': [
                                                                                          'Packmanv10BrandonLaCombe',
                                                                                          'PackmanV10BrandonLaCombe'],
                                                                                      'Architecture': 'x86',
                                                                                      'Called DLLs': ['KERNEL32.DLL',
                                                                                                      'VERSION.dll',
                                                                                                      'COMCTL32.dll',
                                                                                                      'CRYPT32.dll',
                                                                                                      'WINTRUST.dll',
                                                                                                      'ntdll.dll',
                                                                                                      'USER32.dll',
                                                                                                      'GDI32.dll',
                                                                                                      'COMDLG32.dll',
                                                                                                      'ADVAPI32.dll',
                                                                                                      'SHELL32.dll',
                                                                                                      'ole32.dll',
                                                                                                      'OLEAUT32.dll',
                                                                                                      'SHLWAPI.dll',
                                                                                                      'WINHTTP.dll'],
                                                                                      'IP addresses': [],
                                                                                      'Domain names': [], 'URLs': []}),
                                                             ('pecompact_Autoruns.exe', {'Packing status': 'Packed',
                                                                                         'Packers': [
                                                                                             'PECompactV2XBitsumTechnologies',
                                                                                             'PECompact2xxBitSumTechnologies',
                                                                                             'PECompactv2xx', 'pecompact2'],
                                                                                         'Architecture': 'x86',
                                                                                         'Called DLLs': ['kernel32.dll',
                                                                                                         'VERSION.dll',
                                                                                                         'COMCTL32.dll',
                                                                                                         'CRYPT32.dll',
                                                                                                         'WINTRUST.dll',
                                                                                                         'ntdll.dll',
                                                                                                         'USER32.dll',
                                                                                                         'GDI32.dll',
                                                                                                         'COMDLG32.dll',
                                                                                                         'ADVAPI32.dll',
                                                                                                         'SHELL32.dll',
                                                                                                         'ole32.dll',
                                                                                                         'OLEAUT32.dll',
                                                                                                         'SHLWAPI.dll',
                                                                                                         'WINHTTP.dll'],
                                                                                         'IP addresses': [],
                                                                                         'Domain names': [],
                                                                                         'URLs': []}), ('petite_7z.exe',
                                                                                                        {
                                                                                                            'Packing status': 'Packed',
                                                                                                            'Packers': [
                                                                                                                'Petite21',
                                                                                                                'Petitev212',
                                                                                                                'PEtitev21',
                                                                                                                '.petite'],
                                                                                                            'Architecture': 'x86',
                                                                                                            'Called DLLs': [
                                                                                                                'KERNEL32.dll',
                                                                                                                'USER32.dll',
                                                                                                                'ADVAPI32.dll',
                                                                                                                'ole32.dll',
                                                                                                                'OLEAUT32.dll',
                                                                                                                'MSVCRT.dll'],
                                                                                                            'IP addresses': [],
                                                                                                            'Domain names': [],
                                                                                                            'URLs': []}),
                                                             ('rlpack_Autoruns.exe', {'Packing status': 'Packed',
                                                                                      'Packers': ['.packed', '.RLPack'],
                                                                                      'Architecture': 'x86',
                                                                                      'Called DLLs': ['kernel32.dll',
                                                                                                      'VERSION.dll',
                                                                                                      'COMCTL32.dll',
                                                                                                      'CRYPT32.dll',
                                                                                                      'WINTRUST.dll',
                                                                                                      'ntdll.dll',
                                                                                                      'USER32.dll',
                                                                                                      'GDI32.dll',
                                                                                                      'COMDLG32.dll',
                                                                                                      'ADVAPI32.dll',
                                                                                                      'SHELL32.dll',
                                                                                                      'ole32.dll',
                                                                                                      'OLEAUT32.dll',
                                                                                                      'SHLWAPI.dll',
                                                                                                      'WINHTTP.dll'],
                                                                                      'IP addresses': [],
                                                                                      'Domain names': [], 'URLs': []}),
                                                             ('telock_BlueScreenView.exe', {'Packing status': 'Packed',
                                                                                            'Packers': ['tElockv098',
                                                                                                        'tElockv098tE',
                                                                                                        'tElock098tE'],
                                                                                            'Architecture': 'x86',
                                                                                            'Called DLLs': [
                                                                                                'kernel32.dll',
                                                                                                'user32.dll'],
                                                                                            'IP addresses': [],
                                                                                            'Domain names': [],
                                                                                            'URLs': []}), (
                                                             'themida_Autoruns.exe',
                                                             {'Packing status': 'Packed', 'Packers': ['.Themida'],
                                                              'Architecture': 'x86',
                                                              'Called DLLs': ['kernel32.dll', 'VERSION.dll',
                                                                              'COMCTL32.dll', 'CRYPT32.dll',
                                                                              'WINTRUST.dll', 'ntdll.dll', 'USER32.dll',
                                                                              'GDI32.dll', 'COMDLG32.dll',
                                                                              'ADVAPI32.dll', 'SHELL32.dll',
                                                                              'ole32.dll', 'OLEAUT32.dll',
                                                                              'SHLWAPI.dll', 'WINHTTP.dll'],
                                                              'IP addresses': [], 'Domain names': [], 'URLs': []}), (
                                                             'upx_Autoruns.exe', {'Packing status': 'Packed',
                                                                                  'Packers': [
                                                                                      'UPXV200V290MarkusOberhumerLaszloMolnarJohnReiser',
                                                                                      'UPX290LZMAMarkusOberhumerLaszloMolnarJohnReiser',
                                                                                      'upx_3', 'UPX0', 'UPX1'],
                                                                                  'Architecture': 'x86',
                                                                                  'Called DLLs': ['ADVAPI32.dll',
                                                                                                  'COMCTL32.dll',
                                                                                                  'COMDLG32.dll',
                                                                                                  'CRYPT32.dll',
                                                                                                  'GDI32.dll',
                                                                                                  'KERNEL32.DLL',
                                                                                                  'ntdll.dll',
                                                                                                  'ole32.dll',
                                                                                                  'OLEAUT32.dll',
                                                                                                  'SHELL32.dll',
                                                                                                  'SHLWAPI.dll',
                                                                                                  'USER32.dll',
                                                                                                  'VERSION.dll',
                                                                                                  'WINHTTP.dll',
                                                                                                  'WINTRUST.dll'],
                                                                                  'IP addresses': [],
                                                                                  'Domain names': [], 'URLs': []}), (
                                                             'winupack_Autoruns.exe', {'Packing status': 'Packed',
                                                                                       'Packers': [
                                                                                           'WinUpackv039finalrelocatedimagebaseByDwingc2005h2',
                                                                                           'Upack_PatchoranyVersionDwing',
                                                                                           'UpackV037Dwing', '.Upack'],
                                                                                       'Architecture': 'x86',
                                                                                       'Called DLLs': ['KERNEL32.DLL'],
                                                                                       'IP addresses': [],
                                                                                       'Domain names': [], 'URLs': []}),
                                                             ('yoda-crypter_Autoruns.exe', {'Packing status': 'Packed',
                                                                                            'Packers': [
                                                                                                'yodasCrypter13AshkbizDanehkar',
                                                                                                'yoda_crypter_1_3'],
                                                                                            'Architecture': 'x86',
                                                                                            'Called DLLs': [
                                                                                                'KeRnEl32.dLl'],
                                                                                            'IP addresses': [],
                                                                                            'Domain names': [],
                                                                                            'URLs': []}), (
                                                             'yoda-protector_Autoruns.exe', {'Packing status': 'Packed',
                                                                                             'Packers': [
                                                                                                 'YodasProtectorv1032Beta2AshkbizDanehkar',
                                                                                                 'yodasProtector102103AshkbizDanehkar',
                                                                                                 'yodasProtectorV1032AshkbizDanehkar',
                                                                                                 'yodasProtector102AshkibizDanehlar',
                                                                                                 '.yP'],
                                                                                             'Architecture': 'x86',
                                                                                             'Called DLLs': [
                                                                                                 'Kernel32.dll'],
                                                                                             'IP addresses': [],
                                                                                             'Domain names': [],
                                                                                             'URLs': []})]
                             )
    def test_pe_analysis(self, file_manager, file_path, expected_results):
        """
        Test the analysis of PE files for packing, architecture detection, DLL extraction, and content extraction.

        This test verifies that the PEAnalyzer correctly identifies packing status, architecture,
        DLLs used, and correctly extracts URLs, IP addresses, and domain names from the PE file content.

        Args:
            file_manager (FileManager): An instance of the FileManager class.
            file_path (str): The path to the PE file to test.
            expected_results (dict): The expected results of the PE analysis, including packing status,
                                     packer used, architecture, lists of DLLs, URLs, IPs, and domain names.
        """
        file_path = f"tests/resources/pe-files/{file_path}"
        analyzer = PEAnalyzer()
        with patch('analyzers.vt_analyzer.VirusTotalAnalyzer.analyze_vt_report') as mock_analyze_vt:
            mock_analyze_vt.return_value = {}

            result = analyzer.analyze(file_path, 'pe')
            assert result['Packing status'] == expected_results[
                'Packing status'], f"Packing status check failed for {file_path}"
            assert result['Packers'] == expected_results['Packers'], f"Packer detection failed for {file_path}"
            assert result['Architecture'] == expected_results[
                'Architecture'], f"Architecture detection failed for {file_path}"
            assert all(dll in expected_results['Called DLLs'] for dll in
                       result['Called DLLs']), f"Some DLLs were not extracted correctly for {file_path}"
            assert all(url in expected_results['URLs'] for url in
                       result['URLs']), f"Some URLs were not extracted correctly for {file_path}"
            assert all(ip in expected_results['IP addresses'] for ip in
                       result['IP addresses']), f"Some IPs were not extracted correctly for {file_path}"
            assert all(domain in expected_results['Domain names'] for domain in
                       result['Domain names']), f"Some domain names were not extracted correctly for {file_path}"
