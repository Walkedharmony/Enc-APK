from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
from kivy.uix.filechooser import FileChooserListView
from PyPDF2 import PdfFileReader
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import io

class PDFViewer(BoxLayout):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.orientation = 'vertical'
        self.filechooser = FileChooserListView(on_selection=self.load_pdf)
        self.add_widget(self.filechooser)
        self.pdf_label = Label(text='Select an encrypted PDF file to view')
        self.add_widget(self.pdf_label)
        self.key_input = TextInput(hint_text='Enter AES Key', password=True)
        self.add_widget(self.key_input)
        self.load_button = Button(text='Load PDF', on_press=self.decrypt_and_load_pdf)
        self.add_widget(self.load_button)
        self.pdf_path = None

    def load_pdf(self, filechooser, selection):
        self.pdf_path = selection[0] if selection else None

    def decrypt_and_load_pdf(self, instance):
        key = self.key_input.text.encode()
        if self.pdf_path and key:
            try:
                with open(self.pdf_path, 'rb') as f:
                    iv = f.read(16)
                    encrypted_data = f.read()
                    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
                    decryptor = cipher.decryptor()
                    decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
                    
                    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
                    decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()
                    
                    pdf_reader = PdfFileReader(io.BytesIO(decrypted_data))
                    num_pages = pdf_reader.getNumPages()
                    pdf_text = ''
                    for i in range(num_pages):
                        pdf_text += pdf_reader.getPage(i).extract_text()
                    
                    self.pdf_label.text = pdf_text
                    self.pdf_label.text = "PDF successfully decrypted and loaded!"
            except Exception as e:
                self.pdf_label.text = f"Failed to decrypt or load PDF: {str(e)}"

class PDFApp(App):
    def build(self):
        return PDFViewer()

if __name__ == '__main__':
    PDFApp().run()
