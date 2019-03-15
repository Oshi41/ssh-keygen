# ssh-keygen
Генерация ssh ключей в файл

Использование:

go get "github.com/Oshi41/ssh-keygen"

Функция ssh_keygen.GenerateNew(privatePath, publicPath, bitSize)

Генерирует новый ssh ключ с указанным размером блока бит и записывает его в указанные пути. Если передать пустой путь (path == ""), этот файл сохранен не будет. При успешном результате вернет nil. 

Функция ssh_keygen.GenerateNew4096(privatePath, publicPath) использует блок размером 4096 бит и вызывет вышеуказанную функцию
