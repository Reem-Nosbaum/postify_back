from constants.auth import min_pw_len


def signup_pw_validation(pw: str) -> bool:
	"""
	@param pw: the user's pw who tried to log in
	@return: if pw valid True else False
	"""
	return len(pw) >= min_pw_len
