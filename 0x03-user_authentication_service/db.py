#!/usr/bin/env python3
"""DB module
"""
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.session import Session

from user import Base, User


class DB:
    """DB class
    """

    def __init__(self) -> None:
        """Initialize a new DB instance
        """
        self._engine = create_engine("sqlite:///a.db", echo=True)
        Base.metadata.drop_all(self._engine)
        Base.metadata.create_all(self._engine)
        self.__session = None

    @property
    def _session(self) -> Session:
        """Memoized session object
        """
        if self.__session is None:
            DBSession = sessionmaker(bind=self._engine)
            self.__session = DBSession()
        return self.__session

    def add_user(self, email: str, hashed_password: str) -> User:
        """
        Add new user to the database

        Args:
            email: the new user email
            hashed_password: The user password

        Returns:
            new_user: the user object created and added
        """

        new_user = User(email=email, hashed_password=hashed_password)

        self._session.add(new_user)
        self._session.commit()

        return new_user

    def find_user_by(self, **kwargs) -> User:
        """
        Finds a user by arbitrary keyword arguments.
        Args:
            **kwargs: Arbitrary keyword arguments for filtering.
        Returns:
            User: The first user found that matches the criteria.
        Raises:
            NoResultFound: If no user is found.
            InvalidRequestError: If invalid arguments are provided.
        """
        user = self._session.query(User).filter_by(**kwargs).first()
        if not user:
            raise NoResultFound("No user found")
        return user

    def update_user(self, user_id: int, **kwargs) -> None:
        """
        Update a user's attributes.
        Args:
            user_id (int): The ID of the user to update.
            **kwargs: Arbitrary keyword arguments of the attributes to update.
        Returns:
            None: The method doesn't return anything.
        Raises:
            ValueError: If any attribute provided in kwargs does not
            exist in the User model.
        """
        try:
            user = self.find_user_by(id=user_id)
            for key, value in kwargs.items():
                if hasattr(user, key):
                    setattr(user, key, value)
                else:
                    raise InvalidRequestError
            self._session.commit()
        except (NoResultFound, InvalidRequestError, ValueError):
            raise ValueError
