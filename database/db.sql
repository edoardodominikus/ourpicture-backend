
CREATE TABLE
  users (
    id BIGSERIAL PRIMARY KEY,
    email VARCHAR(20) NOT NULL,
    username VARCHAR(20) NOT NULL,
    name VARCHAR(50) NOT NULL,
    profile_picture TEXT NOT NULL,
    password TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP
  );

CREATE TABLE
  posts (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL,
    description TEXT NOT NULL,
    images TEXT[] NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP
  );

CREATE TABLE
  post_likes (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL,
    post_id BIGINT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP
  );