package ssh_keygen

import (
	"os"
	"path/filepath"
	"errors"
	"crypto/rsa"
	"crypto/rand"
	"log"
	"crypto/x509"
	"encoding/pem"
	"golang.org/x/crypto/ssh"
	"io/ioutil"
)

var (
	// Флаг для разрешений при создании файлов/папок
	perm = os.ModePerm
)
// Генерит ключи с дефолтным размером блока бит
func GenerateNew4096(privatePath, publicPath string) error {
	return GenerateNew(privatePath, publicPath, 4096)
}

// Создает новую пару ssh ключей, записывает их в указанные пути
// Если путей не существует, они будут созданы.
func GenerateNew(privatePath, publicPath string, bitsize int) error {
	writePublic := checkAndCreateFiles(publicPath)
	writePrivate := checkAndCreateFiles(privatePath)

	if writePrivate != nil && writePublic != nil {
		return errors.New("Wrong paths: " + privatePath + " " + publicPath)
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, bitsize)
	if err != nil{
		return err
	}

	err = privateKey.Validate()
	if err != nil{
		return err
	}

	log.Println("key generated")

	if writePublic != nil{
		publicBytes, err := publicPEMBytes(&privateKey.PublicKey)
		if err != nil{
			return err
		}

		err = write(publicPath, publicBytes)
		if err != nil{
			return err
		}
	}

	if writePrivate != nil{
		privateBytes := privatePEMBytes(privateKey)
		err = write(privatePath, privateBytes)
		if err != nil{
			return err
		}
	}

	return nil
}

// Проверяет наличие папок и самого файлы
func checkAndCreateFiles(path string) error{
	// Путь пустой, возвращаем ошибьку
	if path == ""{
		return os.ErrNotExist
	}

	// Получили папку
	dir := filepath.Dir(path)

	// Создали папку, если её нет
	if !fileExist(dir){
	 	err := os.MkdirAll(dir, perm)
	 	if err != nil{
	 		return err
		}
	}

	// Првоеряем наличие файла
	if !fileExist(path){
		file, err := os.Create(path)
		if err != nil{
			return err
		} else {
			return file.Close()
		}
	}

	return nil
}

// Проверяет наличие файла по указанному пути
func fileExist(path string) bool {
	_, err := os.Stat(path)

	return !os.IsNotExist(err)
}

// Кодирует приватный ключ в PEM формат
func privatePEMBytes(key *rsa.PrivateKey) []byte {
	// Get ASN.1 DER format
	bytes := x509.MarshalPKCS1PrivateKey(key)

	// pem.Block
	block := pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   bytes,
	}

	// Private key in PEM format
	privatePEM := pem.EncodeToMemory(&block)

	return privatePEM
}

// Кодирует публичную часть ключа в PEM формат
func publicPEMBytes(key *rsa.PublicKey) ([] byte, error){
	publicRsaKey, err := ssh.NewPublicKey(key)
	if err != nil {
		return nil, err
	}

	pubKeyBytes := ssh.MarshalAuthorizedKey(publicRsaKey)

	return pubKeyBytes, nil
}

// Записываем данные в файл и логируем
func write(path string, content []byte )  error {
	err := ioutil.WriteFile(path, content, perm)
	if err != nil{
		return err
	}

	log.Printf("Key saved to: %s", path)
	return nil
}
