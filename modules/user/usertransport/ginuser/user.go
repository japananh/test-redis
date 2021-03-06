package ginuser

import (
	"app-invite-service/common"
	"app-invite-service/component"
	"app-invite-service/component/hash"
	"app-invite-service/component/tokenprovider/jwt"
	"app-invite-service/modules/user/userbiz"
	"app-invite-service/modules/user/usermodel"
	"app-invite-service/modules/user/userstorage"
	"net/http"

	"github.com/gin-gonic/gin"
)

func Login(appCtx component.AppContext) gin.HandlerFunc {
	return func(c *gin.Context) {
		var data usermodel.UserLogin

		if err := c.ShouldBind(&data); err != nil {
			panic(common.ErrInvalidRequest(err))
		}

		db := appCtx.GetMainDBConnection()
		store := userstorage.NewSQLStore(db)
		tokenProvider := jwt.NewTokenJWTProvider(appCtx.SecretKey())
		md5 := hash.NewMd5Hash()
		tokenConfig := appCtx.GetTokenConfig()

		biz := userbiz.NewLoginBiz(store, tokenProvider, md5, tokenConfig)

		account, err := biz.Login(c.Request.Context(), &data)
		if err != nil {
			panic(err)
		}

		c.JSON(http.StatusOK, common.SimpleSuccessResponse(account))
	}
}

func Register(appCtx component.AppContext) gin.HandlerFunc {
	return func(c *gin.Context) {
		var data usermodel.UserCreate

		if err := c.ShouldBind(&data); err != nil {
			panic(common.ErrInvalidRequest(err))
		}

		db := appCtx.GetMainDBConnection()
		store := userstorage.NewSQLStore(db)
		md5 := hash.NewMd5Hash()
		biz := userbiz.NewRegisterBiz(store, md5)

		if err := biz.Register(c.Request.Context(), &data); err != nil {
			panic(err)
		}

		c.JSON(http.StatusOK, common.SimpleSuccessResponse(data.Id))
	}
}

func GenerateInviteToken(appCtx component.AppContext) gin.HandlerFunc {
	return func(c *gin.Context) {
		//db := appCtx.GetMainDBConnection()
		redis := appCtx.GetRedisConnection()
		//store := userstorage.NewSQLStore(db)
		biz := userbiz.NewGenerateTokenBiz(redis)

		result, err := biz.GenerateToken(c.Request.Context())
		if err != nil {
			panic(err)
		}

		c.JSON(http.StatusOK, common.SimpleSuccessResponse(result))
	}
}
