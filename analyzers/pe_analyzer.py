import pefile
import yara
import json
from analyzers.file_analyzer import FileAnalyzer
from utils import DataExtractor, calculate_entropy
import datetime
import re
import os


class PEAnalyzer(FileAnalyzer, DataExtractor):
    def __init__(self, file_path):
        super().__init__()
        self.packer_rules = yara.compile('packing-rules/packer.yar')
        self.crypto_rules = yara.compile('packing-rules/crypto.yar')
        self.peid_rules = yara.compile('packing-rules/peid.yar')
        self.packers_sections = json.load(open('packing-rules/packer-sections.json', 'r'))
        self.file_path = file_path
        self.pe = pefile.PE(file_path)
        self.strings = self.extract_strings()

    def extract_strings(self):
        strings = []
        for section in self.pe.sections:
            data = section.get_data()
            strings += re.findall(b'[\\w\\-]{4,}', data)
        return ' '.join(s.decode('utf-8', errors='ignore') for s in strings)

    def get_architecture(self):
        architecture = {
            0x014c: "x86",
            0x8664: "x64"
        }
        return architecture.get(self.pe.FILE_HEADER.Machine, "Unknown architecture")

    def get_general_entropy(self):
        return calculate_entropy(self.pe.__data__)

    def get_file_size(self):
        return os.path.getsize(self.file_path)

    def get_sections_info(self):
        sections_info = []
        for section in self.pe.sections:
            try:
                name = section.Name.decode('utf-8').strip()
            except UnicodeDecodeError:
                name = section.Name.hex()
            sections_info.append({
                "Name": name,
                "Entropy": calculate_entropy(section.get_data()),
                "Virtual Size": section.Misc_VirtualSize,
                "Raw Size": section.SizeOfRawData
            })
        return sections_info

    def get_compilation_date(self):
        timestamp = self.pe.FILE_HEADER.TimeDateStamp
        return datetime.datetime.utcfromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')

    def get_called_dlls(self):
        dlls = []
        if hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                dlls.append(entry.dll.decode())
        else:
            dlls.append("No import table found")
        return dlls

    def yara_matches(self, rules):
        try:
            matches = rules.match(self.file_path)
            if matches:
                matches_as_strings = [str(match) for match in matches]
                return matches_as_strings
            return []
        except Exception as e:
            print(f"YARA matching exception: {str(e)}")
            return []

    def detect_packing(self, sections_of_pe):
        sections_keys = self.packers_sections
        return [sections_keys[x.lower()] for x in sections_of_pe if x.lower() in sections_keys.keys()]

    def packing_section_matches(self):
        try:
            exe = pefile.PE(
                self.file_path,
                fast_load=True)
            matches = self.detect_packing([
                section.Name.decode(errors='replace', ).rstrip('\x00') for section in exe.sections
            ])
            if matches:
                return matches
            return []
        except Exception as e:
            return []

    def identify_packers(self):
        matches = self.yara_matches(self.packer_rules)
        matches.extend(self.packing_section_matches())
        return matches

    def identify_cryptors(self):
        matches = self.yara_matches(self.crypto_rules)
        return matches

    def analyze(self):
        return {
            "Architecture": self.get_architecture(),
            "General Entropy": self.get_general_entropy(),
            "File Size": self.get_file_size(),
            "Sections Info": self.get_sections_info(),
            "Compilation Date": self.get_compilation_date(),
            "Called DLLs": self.get_called_dlls(),
            "URLs": list(self.extract_urls(self.strings)),
            "Domain names": list(self.extract_domains(self.strings)),
            "IP addresses": list(self.extract_ips(self.strings)),
            "Packing status": "Packed" if self.identify_packers() else "Not Packed",
            "Packers": self.identify_packers(),
            "Cryptors": self.identify_cryptors()
        }
