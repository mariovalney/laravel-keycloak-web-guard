<?php

namespace Vizir\KeycloakWebGuard\Middleware;

use Closure;
use Illuminate\Support\Facades\Auth;
use Vizir\KeycloakWebGuard\Exceptions\KeycloakCanException;
use App\Providers\RouteServiceProvider;

class KeycloakCan extends KeycloakAuthenticated
{
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @param  string|null  $guard
     * @return mixed
     */
    public function handle($request, Closure $next, ...$guards)
    {
        if (empty($guards) && Auth::check()) {
            return $next($request);
        }

        $guards = explode('|', ($guards[0] ?? ''));
        if (Auth::hasRole($guards)) {
            return $next($request);
        }
        
        if (Auth::check()) {
            return redirect(RouteServiceProvider::HOME);
        }

        throw new KeycloakCanException(
            'Unauthenticated.', $guards, $this->redirectTo($request)
        );
    }
}
