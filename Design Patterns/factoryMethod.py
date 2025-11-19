#Without Factory Method

class EmailNotifier:
    def send(self, message):
        print("Email:", message)

class SMSNotifier:
    def send(self, message):
        print("SMS:", message)


def main():
    method = input("Choose method (email/sms): ")

    if method == "email":
        notifier = EmailNotifier()
    elif method == "sms":
        notifier = SMSNotifier()
    else:
        raise ValueError("Unknown method")

    notifier.send("Hello there!")

main()

#With Factory Method
class EmailNotifier:
    def send(self, message):
        print("Email:", message)

class SMSNotifier:
    def send(self, message):
        print("SMS:", message)


def notifier_factory(method):
    if method == "email":
        return EmailNotifier()
    elif method == "sms":
        return SMSNotifier()
    else:
        raise ValueError("Unknown method")


def main():
    method = input("Choose method (email/sms): ")
    notifier = notifier_factory(method)  # main doesn't know details
    notifier.send("Hello there!")

main()


