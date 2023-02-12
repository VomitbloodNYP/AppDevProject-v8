class PersonalDetails:
    def __init__(self, account_id, city, full_name, phone_number, zip, address, card_number, card_holder_name, expiry_date, cvv):
        self.__account_id = account_id
        self.__city = city
        self.__full_name = full_name
        self.__phone_number = phone_number
        self.__zip = zip
        self.__address = address
        self.__card_number = card_number
        self.__card_holder_name = card_holder_name
        self.__expiry_date = expiry_date
        self.__cvv = cvv

    def get_account_id(self):
        return self.__account_id

    def get_city(self):
        return self.__city

    def get_full_name(self):
        return self.__full_name

    def get_phone_number(self):
        return self.__phone_number

    def get_zip(self):
        return self.__zip

    def get_address(self):
        return self.__address

    def get_card_number(self):
        return self.__card_number

    def get_card_holder_name(self):
        return self.__card_holder_name

    def get_expiry_date(self):
        return self.__expiry_date

    def get_cvv(self):
        return self.__cvv

    def set_account_id(self, account_id):
        self.__account_id = account_id

    def set_city(self, city):
        self.__city = city

    def set_full_name(self, full_name):
        self.__full_name = full_name

    def set_phone_number(self, phone_number):
        self.__phone_number = phone_number

    def set_zip(self, zip):
        self.__zip = zip

    def set_address(self, address):
        self.__address = address

    def set_card_number(self, card_number):
        self.__card_number = card_number

    def set_card_holder_name(self, card_holder_name):
        self.__card_holder_name = card_holder_name

    def set_expiry_date(self, expiry_date):
        self.__expiry_date = expiry_date

    def set_cvv(self, cvv):
        self.__cvv = cvv
