-- MySQL Workbench Forward Engineering

SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0;
SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0;
SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='ONLY_FULL_GROUP_BY,STRICT_TRANS_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION';

-- -----------------------------------------------------
-- Schema mydb
-- -----------------------------------------------------
-- -----------------------------------------------------
-- Schema is_chat
-- -----------------------------------------------------

-- -----------------------------------------------------
-- Schema is_chat
-- -----------------------------------------------------
CREATE SCHEMA IF NOT EXISTS `is_chat` DEFAULT CHARACTER SET utf8mb3 ;
USE `is_chat` ;

-- -----------------------------------------------------
-- Table `is_chat`.`users`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `is_chat`.`users` ;

CREATE TABLE IF NOT EXISTS `is_chat`.`users` (
  `username` VARCHAR(20) NOT NULL,
  `password` CHAR(64) NOT NULL,
  `salt` CHAR(64) NOT NULL,
  `public_key` BLOB NOT NULL,
  PRIMARY KEY (`username`),
  UNIQUE INDEX `salt_UNIQUE` (`salt` ASC) VISIBLE)
ENGINE = InnoDB
DEFAULT CHARACTER SET = utf8mb3;


-- -----------------------------------------------------
-- Table `is_chat`.`groups`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `is_chat`.`groups` ;

CREATE TABLE IF NOT EXISTS `is_chat`.`groups` (
  `group_id` INT NOT NULL AUTO_INCREMENT,
  `group_name` VARCHAR(45) NOT NULL,
  `admin` VARCHAR(20) NOT NULL,
  PRIMARY KEY (`group_id`),
  UNIQUE INDEX `group_name_UNIQUE` (`group_name` ASC) VISIBLE,
  INDEX `username_idx` (`admin` ASC) VISIBLE,
  CONSTRAINT `adminFK`
    FOREIGN KEY (`admin`)
    REFERENCES `is_chat`.`users` (`username`)
    ON UPDATE CASCADE)
ENGINE = InnoDB
AUTO_INCREMENT = 6
DEFAULT CHARACTER SET = utf8mb3;


-- -----------------------------------------------------
-- Table `is_chat`.`group_messages`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `is_chat`.`group_messages` ;

CREATE TABLE IF NOT EXISTS `is_chat`.`group_messages` (
  `group_id` INT NOT NULL,
  `sender` VARCHAR(20) NOT NULL,
  `message` BLOB NOT NULL,
  `time` DATETIME NOT NULL,
  INDEX `group_idFK_idx` (`group_id` ASC) VISIBLE,
  INDEX `senderFK_idx` (`sender` ASC) VISIBLE,
  CONSTRAINT `group_idFK_group_messages`
    FOREIGN KEY (`group_id`)
    REFERENCES `is_chat`.`groups` (`group_id`),
  CONSTRAINT `senderFK`
    FOREIGN KEY (`sender`)
    REFERENCES `is_chat`.`users` (`username`))
ENGINE = InnoDB
DEFAULT CHARACTER SET = utf8mb3;


-- -----------------------------------------------------
-- Table `is_chat`.`key_storage`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `is_chat`.`key_storage` ;

CREATE TABLE IF NOT EXISTS `is_chat`.`key_storage` (
  `group_id` INT NOT NULL,
  `key` CHAR(32) NOT NULL,
  PRIMARY KEY (`group_id`),
  UNIQUE INDEX `key_UNIQUE` (`key` ASC) VISIBLE,
  CONSTRAINT `group_idFK_key_storage`
    FOREIGN KEY (`group_id`)
    REFERENCES `is_chat`.`groups` (`group_id`)
    ON DELETE CASCADE)
ENGINE = InnoDB
DEFAULT CHARACTER SET = utf8mb3;


-- -----------------------------------------------------
-- Table `is_chat`.`user_group`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `is_chat`.`user_group` ;

CREATE TABLE IF NOT EXISTS `is_chat`.`user_group` (
  `username` VARCHAR(20) NOT NULL,
  `group_id` INT NOT NULL,
  PRIMARY KEY (`username`, `group_id`),
  INDEX `username_idx` (`username` ASC) VISIBLE,
  INDEX `group_idFK_idx` (`group_id` ASC) VISIBLE,
  CONSTRAINT `group_idFK_user_group`
    FOREIGN KEY (`group_id`)
    REFERENCES `is_chat`.`groups` (`group_id`)
    ON DELETE CASCADE,
  CONSTRAINT `usernameFK`
    FOREIGN KEY (`username`)
    REFERENCES `is_chat`.`users` (`username`)
    ON DELETE CASCADE)
ENGINE = InnoDB
DEFAULT CHARACTER SET = utf8mb3;


SET SQL_MODE=@OLD_SQL_MODE;
SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS;
SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS;
