def individual_user_data(user):
    """
    Format individual user data for response.

    Args:
        user (dict): User data dictionary.

    Returns:
        dict: Formatted user data.
    """
    return {
        "user_id": str(user["user_id"]),
        "username": user["username"],
        "full_name": user["full_name"],
        "email": user["email"],
        "password": user["password"],
        "is_active": user["is_active"],
        "is_admin": user["is_admin"],
        "credits": user["credits"],
        "date_created": user["date_created"],
        "date_updated": user["date_updated"],
    }


def all_users_data(users):
    """
    Format all users data for response.

    Args:
        users (list): List of user data dictionaries.

    Returns:
        list: Formatted list of user data.
    """
    return [individual_user_data(user) for user in users]
