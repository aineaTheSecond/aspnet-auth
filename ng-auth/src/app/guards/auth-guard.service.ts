import { HttpClient, HttpHeaders } from "@angular/common/http";
import { Injectable } from "@angular/core";
import { CanActivate, Router } from "@angular/router";
import { JwtHelperService } from "@auth0/angular-jwt";

@Injectable()
export class AuthGuard implements CanActivate {
  constructor(
    private jwtHelper: JwtHelperService,
    private router: Router,
    private http: HttpClient
  ) {}

  async canActivate() {
    const token = localStorage.getItem("jwt");

    if (token && this.jwtHelper.isTokenExpired(token)) {
      return true;
    }

    const isRefreshSuccess = await this.tryRefreshingTokens(token);

    this.router.navigate(["login"]);
    return isRefreshSuccess;
  }

  private async tryRefreshingTokens(token: string): Promise<boolean> {
    const refreshToken: string = localStorage.getItem("refreshToken");

    if (!token || !refreshToken) return false;

    const credentials = JSON.stringify({
      accessToken: token,
      refreshToken: refreshToken,
    });

    let isRefreshSuccess: boolean;
    try {
      const response = await this.http
        .post("http://localhost:5000/api/token/refresh", credentials, {
          headers: new HttpHeaders({ "Content-Type": "application/json" }),
          observe: "response",
        })
        .toPromise();

      const newToken = (<any>response).body.accessToken;
      const newRefreshToken = (<any>response).body.refreshToken;

      localStorage.setItem("jwt", newToken);
      localStorage.setItem("refreshToken", refreshToken);
      isRefreshSuccess = true;
    } catch (ex) {
      isRefreshSuccess = false;
    }

    return isRefreshSuccess;
  }
}
