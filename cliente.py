import socket
import json
from base64 import b64encode

def enviar(comando):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(("127.0.0.1", 8888))
        s.send(json.dumps(comando).encode())
        resposta = s.recv(1000000000)
        return json.loads(resposta.decode())

# LOGIN
resposta = enviar({"acao": "login", "usuario": "bertrand"})
print(resposta)

# ASSINAR PDF
with open("pdf_exemplo.pdf", "rb") as f:
    conteudo = f.read()

resposta = enviar({
    "acao": "sign",
    "nome_arquivo": "pdf_exemplo.pdf",
    "conteudo_pdf": b64encode(conteudo).decode()
})
print("Assinatura:", resposta["assinatura"])

# VERIFICAR
resposta = enviar({
    "acao": "verify",
    "nome_arquivo": "pdf_exemplo.pdf",
    "conteudo_pdf": b64encode(conteudo).decode()
})
print("Assinatura válida?", resposta["valido"])
