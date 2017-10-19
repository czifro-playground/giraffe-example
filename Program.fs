module GiraffeExample.App

  open System
  open System.Collections.Generic
  open System.IO
  open System.Security.Claims
  open System.Text
  open System.Security.Cryptography
  open System.IdentityModel.Tokens.Jwt
  open Microsoft.AspNetCore.Authentication
  open Microsoft.AspNetCore.Authentication.JwtBearer
  open Microsoft.AspNetCore.Builder
  open Microsoft.AspNetCore.Hosting
  open Microsoft.AspNetCore.Http
  open Microsoft.Extensions.Logging
  open Microsoft.Extensions.DependencyInjection
  open Microsoft.IdentityModel.Tokens
  open Newtonsoft.Json
  open Giraffe.HttpHandlers
  open Giraffe.Middleware

// ---------------------------------
// Web app
// ---------------------------------

  type SimpleClaim = { Type: string; Value: string }
  type Token = { access_token: string; expires_in: int }

  let secretKey = "mysupersecret_secretkey!123"
  let signingKey = SymmetricSecurityKey(Encoding.ASCII.GetBytes(secretKey))
  let signingCredentials =
    SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256)

  let authorize =
    requiresAuthentication (challenge JwtBearerDefaults.AuthenticationScheme)

  let greet =
    fun (next : HttpFunc) (ctx : HttpContext) ->
      let claim = ctx.User.FindFirst "name"
      let name = claim.Value
      text ("Hello " + name) next ctx
    
  let showClaims =
    fun (next : HttpFunc) (ctx : HttpContext) ->
      let claims = ctx.User.Claims
      let simpleClaims = Seq.map (fun (i : Claim) -> {Type = i.Type; Value = i.Value}) claims
      json simpleClaims next ctx

  let token =
    fun (next : HttpFunc) (ctx : HttpContext) ->
      if not (ctx.Request.Form.ContainsKey("username")) ||
        not (ctx.Request.Form.ContainsKey("password")) then
        ctx.Response.StatusCode <- 400
        ctx.Response.WriteAsync("Invalid username or password").Wait()
        next ctx
      else
        let username =
          let mutable u = Microsoft.Extensions.Primitives.StringValues()
          if ctx.Request.Form.TryGetValue("username",&u) then
            u.Item 0
          else ""
        let password =
          let mutable p = Microsoft.Extensions.Primitives.StringValues()
          if ctx.Request.Form.TryGetValue("password",&p) then
            p.Item 0
          else ""
        let claims =
          [
            Claim(JwtRegisteredClaimNames.Sub, username)
            Claim("name", username)
            Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            Claim(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString())
          ]
        let now = DateTime.UtcNow
        let jwt =
          JwtSecurityToken(
            "GiraffeExample",
            "GiraffeExampleAudience",
            claims,
            Nullable.op_Implicit(now),
            Nullable.op_Implicit(now.AddDays(14.0)),
            signingCredentials
          )
        let encodedJwt = JwtSecurityTokenHandler().WriteToken(jwt)
        let resp =
          {
            access_token = encodedJwt
            expires_in = int (TimeSpan(14,0,0,0).TotalSeconds)
          }
        json resp next ctx

  let validator =
    let encode (input:string) key =
      use hmacSha = new HMACSHA256(key)
      use stream = new MemoryStream(Encoding.UTF8.GetBytes(input))
      Base64UrlEncoder.Encode(hmacSha.ComputeHash stream)
    fun token (parameters:TokenValidationParameters) ->
      let jwt = JwtSecurityToken(token)
      let signKey = signingCredentials.Key :?> SymmetricSecurityKey

      let encodedData = sprintf "%s.%s" jwt.EncodedHeader jwt.EncodedPayload
      let signature = encode encodedData signKey.Key

      if signature <> jwt.RawSignature then
        raise (Exception("Token signature validation failed"))
      jwt :> SecurityToken


  let webApp =
    choose [
      GET >=>
        choose [
          route "/" >=> text "Public endpoint."
          route "/greet" >=> authorize >=> greet
          route "/claims" >=> authorize >=> showClaims
        ]
      POST >=>
        choose [
          route "/token" >=> token
        ]
      setStatusCode 404 >=> text "Not Found" ]

// ---------------------------------
// Error handler
// ---------------------------------

  let errorHandler (ex : Exception) (logger : ILogger) =
    logger.LogError(EventId(), ex, "An unhandled exception has occurred while executing the request.")
    clearResponse >=> setStatusCode 500 >=> text ex.Message

// ---------------------------------
// Config and Main
// ---------------------------------

  let configureApp (app : IApplicationBuilder) =
    app.UseAuthentication() |> ignore
    app.UseGiraffeErrorHandler errorHandler
    app.UseStaticFiles() |> ignore
    app.UseGiraffe webApp

  let authenticationOptions (o : AuthenticationOptions) =
    o.DefaultAuthenticateScheme <- JwtBearerDefaults.AuthenticationScheme
    o.DefaultChallengeScheme <- JwtBearerDefaults.AuthenticationScheme

  let jwtBearerOptions (cfg : JwtBearerOptions) =
    cfg.SaveToken <- true
    cfg.IncludeErrorDetails <- true
    // cfg.Authority <- "https://localhost:5000"
    cfg.Audience <- "GiraffeExampleAudience"
    cfg.TokenValidationParameters <- TokenValidationParameters (
      ValidIssuer = "GiraffeExample"
    )
    cfg.TokenValidationParameters.SignatureValidator <- SignatureValidator(validator)
    

  let configureServices (services : IServiceCollection) =
    services
      .AddAuthentication(authenticationOptions)
      .AddJwtBearer(Action<JwtBearerOptions> jwtBearerOptions) |> ignore

  let configureLogging (builder : ILoggingBuilder) =
    let filter (l : LogLevel) = l.Equals LogLevel.Error
    builder.AddFilter(filter).AddConsole().AddDebug() |> ignore

  [<EntryPoint>]
  let main argv =
    let contentRoot = Directory.GetCurrentDirectory()
    let webRoot     = Path.Combine(contentRoot, "WebRoot")
    WebHostBuilder()
      .UseKestrel()
      .UseContentRoot(contentRoot)
      .UseIISIntegration()
      .UseWebRoot(webRoot)
      .Configure(Action<IApplicationBuilder> configureApp)
      .ConfigureServices(configureServices)
      .ConfigureLogging(configureLogging)
      .Build()
      .Run()
    0