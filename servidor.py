import socket
import json
import hashlib
import os
from base64 import b64encode, b64decode
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.exceptions import InvalidSignature

# Geração das chaves (se não existirem)
os.makedirs("keys", exist_ok=True)
if not os.path.exists("keys/private_key.pem"):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with open("keys/private_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()
        ))
    with open("keys/public_key.pem", "wb") as f:
        f.write(private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        ))
else:
    with open("keys/private_key.pem", "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

# Arquivo de assinaturas
ASSINATURAS_ARQUIVO = "assinaturas.json"
assinaturas = {}
if os.path.exists(ASSINATURAS_ARQUIVO):
    with open(ASSINATURAS_ARQUIVO, "r") as f:
        assinaturas = json.load(f)

def salvar_assinaturas():
    with open(ASSINATURAS_ARQUIVO, "w") as f:
        json.dump(assinaturas, f, indent=2)

def hash_pdf(pdf_bytes):
    return hashlib.sha256(pdf_bytes).digest()

def assinar_hash(h):
    return private_key.sign(
        h,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )

def verificar_assinatura(assinatura, hash_pdf_bytes):
    try:
        public_key = private_key.public_key()
        public_key.verify(
            assinatura,
            hash_pdf_bytes,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False

def processar(mensagem):
    acao = mensagem.get("acao")

    if acao == "login":
        return {"status": "ok", "mensagem": f"Bem-vindo, {mensagem['usuario']}"}

    elif acao == "sign":
        nome = mensagem["nome_arquivo"]
        conteudo = b64decode(mensagem["conteudo_pdf"])
        h = hash_pdf(conteudo)
        assinatura = assinar_hash(h)
        assinatura_b64 = b64encode(assinatura).decode()

        assinaturas[nome] = {
            "assinatura": assinatura_b64,
            "hash": hashlib.sha256(conteudo).hexdigest(),
        }
        salvar_assinaturas()

        return {"status": "ok", "assinatura": assinatura_b64}

    elif acao == "verify":
        nome = mensagem["nome_arquivo"]
        conteudo = b64decode(mensagem["conteudo_pdf"])
        assinatura_b64 = mensagem["assinatura"]
        assinatura = b64decode(assinatura_b64)
        h = hash_pdf(conteudo)
        valido = verificar_assinatura(assinatura, h)
        return {"status": "ok", "valido": valido}

    return {"status": "erro", "mensagem": "Ação desconhecida"}

# Servidor com loop para múltiplas conexões
HOST = "127.0.0.1"
PORT = 8888
print(f"Servidor rodando em {HOST}:{PORT}...")

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen()
    print("Servidor pronto, aguardando conexões...")

    while True:
        conn, addr = s.accept()
        with conn:
            print("Cliente conectado:", addr)
            while True:
                data = conn.recv(100000)
                if not data:
                    break
                try:
                    mensagem = json.loads(data.decode())
                    resposta = processar(mensagem)
                    conn.send(json.dumps(resposta).encode())
                except Exception as e:
                    print("Erro ao processar cliente:", e)
                    break
            print("Cliente desconectado:", addr)
