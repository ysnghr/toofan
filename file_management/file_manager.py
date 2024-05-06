import magic


class FileManager:
    def __init__(self):
        self.magic = magic.Magic(mime=True)
        self.mime_to_extension = {
            'application/pdf': 'pdf',
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document': 'docx',
            'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': 'xlsx',
            'application/vnd.openxmlformats-officedocument.presentationml.presentation': 'pptx',
            # TODO: Add more MIME types and corresponding file extensions as needed
        }

    def identify_file_type(self, file_path):
        mime_type = self.magic.from_file(file_path)
        file_extension = self.mime_to_extension.get(mime_type, '')  # Get corresponding extension
        return file_extension if file_extension else mime_type
