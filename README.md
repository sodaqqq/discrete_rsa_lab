
# Розподіл роботи

Робота була розділена приблизно порівну. Над реалізацією RSA працював **Стас**, над рештою **Остап**. Попередній план роботи та всі деталі реалізації обговорювалися безпосередньо під час написання.

# Звіт

Реалізовано хешування повідомлення перед шифруванням.
Після хешування повідомлення перетворюється у `int`, шифрується за допомогою RSA а потім переводиться назад у байти.
Композиція фінального повідомлення для відправлення виглядає як:
(**хеш + зашифроване повідомлення**)

На стороні одержувача реалізована перевірка цілісності. Спочатку одержувач розбиває повідомлення на хеш (перші 32 байти) та саме зашифроване повідомлення.
Потім дешифрує, обчислює SHA-256 та порівнює.

SHA-256 використана тут через її відому надійність і поки що немає відомих слабких місць. Також має стабільну довжину в 32 байти що спрощує розділити дані на хеш та тіло.

Значення 8192 в `recv(n)` обрано через оптимальність. 8192 байтів вистачає для більшості випадків.


### RSA

В `generate_prime()` генерується рандомне непарне число зі встановленим старшим бітом.
Тестується на простоту методом Міллера-Рабіна.
Використано `secrets.randbits()` адже це безпечний генератор, на відміну від простого `random`.

Для генерації ключів обираються два числа `p` та `q`.
Обчислюється модуль `n = p * q`
Обчислюється `φ(n) = (p - 1)(q - 1)`
Експонента (`e`) = `0x10001 = 65537` (в десятковій системі). Це стандартне значення, яке є простим числом а також дуже легке для обчислень через свій двійковий вигляд.
Обернене до `e` по модулю `φ(n)` дає  експоненту `d`.

Шифрування відбувається по класичній схемі.
Повідомлення переводиться в `int`.
Потім підноситься до степеня `e` по модулю `n`.

Розшифрування теж працює по класичній схемі.