class Review:

    def __init__(self, user_id, name, reviews):
        self.__user_id = user_id
        self.__name = name
        self.__reviews = reviews

    def get_user_id(self):
        return self.__user_id

    def get_name(self):
        return self.__name

    def get_reviews(self):
        return self.__reviews

    def set_user_id(self, user_id):
        self.__user_id = user_id

    def set_name(self, name):
        self.__name = name

    def set_reviews(self, reviews):
        self.__reviews = reviews
