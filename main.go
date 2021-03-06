package main

import (
	"app-invite-service/common"
	"app-invite-service/component/tokenprovider"
	"app-invite-service/server"
	"context"
	"fmt"
	"github.com/go-redis/redis/v8"
	_ "github.com/go-sql-driver/mysql"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"log"
	"time"
)

var ctx = context.Background()

func main() {
	// Load config
	config := common.NewConfig()
	if err := config.Load("."); err != nil {
		log.Fatalln("cannot load config from env file", err)
	}

	dbConn, err := gorm.Open(mysql.Open(config.DBConnectionURL()), &gorm.Config{})
	if err != nil {
		log.Fatalln("cannot open database connection:", err)
	}

	// Redis
	rdb := redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("localhost:%d", config.RedisPort()),
		Password: config.RedisPassword(), // no password set
		DB:       0,                      // use default DB
	})

	err = rdb.Set(ctx, "key", "value", 0).Err()
	if err != nil {
		log.Fatalln(err)
	}

	val, err := rdb.SetNX(ctx, "key", "value", common.InviteTokenExpirySecond*time.Second).Result()
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Println(val, "====")
	// create token configs
	tokenConfig, err := tokenprovider.NewTokenConfig(config.AtExpiry(), config.RtExpiry())
	if err != nil {
		log.Fatalln("cannot create token config", err)
	}

	s := server.Server{
		Port:        config.AppPort(),
		AppEnv:      config.AppEnv(),
		SecretKey:   config.SecretKey(),
		DBConn:      dbConn,
		RedisConn:   rdb,
		TokenConfig: tokenConfig,
		ServerReady: make(chan bool),
	}

	go func() {
		<-s.ServerReady
		close(s.ServerReady)
	}()

	s.RunMigration(config.DBConnectionURL())
	s.Start()
}
