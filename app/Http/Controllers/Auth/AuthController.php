<?php
namespace Lio\Http\Controllers\Auth;

use Lio\Accounts\User;
use Lio\Accounts\UserCreator;
use Lio\Accounts\UserCreatorListener;
use Lio\Accounts\UserRepository;
use Lio\Accounts\SendConfirmationEmail;
use Lio\Http\Controllers\Controller;
use Illuminate\Foundation\Auth\ThrottlesLogins;
use Illuminate\Foundation\Auth\AuthenticatesAndRegistersUsers;
use Request;
use Input;
use Session;
use Auth;
use Validator;

class AuthController extends Controller implements UserCreatorListener
{

    /*
     * |--------------------------------------------------------------------------
     * | Registration & Login Controller
     * |--------------------------------------------------------------------------
     * |
     * | This controller handles the registration of new users, as well as the
     * | authentication of existing users. By default, this controller uses
     * | a simple trait to add these behaviors. Why don't you explore it?
     * |
     */
    
    /**
     *
     * @var \Lio\Accounts\UserRepository
     */
    private $users;

    /**
     *
     * @var \Lio\Accounts\UserCreator
     */
    private $userCreator;

    /**
     *
     * @var \Lio\Accounts\SendConfirmationEmail
     */
    private $confirmation;
    
    use AuthenticatesAndRegistersUsers, ThrottlesLogins;

    /**
     * Create a new authentication controller instance.
     *
     * @return void
     */
    public function __construct(UserRepository $users, UserCreator $userCreator, SendConfirmationEmail $confirmation)
    {
        $this->users = $users;
        $this->userCreator = $userCreator;
        $this->confirmation = $confirmation;
        
        $this->middleware('guest', [
            'except' => [
                'logout',
                'confirmEmail',
                'resendEmailConfirmation'
            ]
        ]);
    }

    /**
     * Get a validator for an incoming registration request.
     *
     * @param array $data            
     * @return \Illuminate\Contracts\Validation\Validator
     */
    protected function validator(array $data)
    {
        return Validator::make($data, [
            'name' => 'required|max:255',
            'email' => 'required|email|max:255|unique:users',
            'password' => 'required|confirmed|min:6'
        ]);
    }

    /**
     * Create a new user instance after a valid registration.
     *
     * @param array $data            
     * @return User
     */
    protected function create(array $data)
    {
        return $this->userCreator->create($this, [
            'name' => $data['name'],
            'email' => $data['email'],
            'password' => bcrypt($data['password']),
            'ip' => Request::ip()
        ]);
    }

    /**
     * Redirect the user to the GitHub authentication page.
     *
     * @return \Illuminate\Http\RedirectResponse
     */
    public function login()
    {
        if (view()->exists('auth.authenticate')) {
            return view('auth.authenticate');
        }
        return view('auth.login');
    }

    /**
     *
     * @return \Illuminate\Http\RedirectResponse|\Illuminate\View\View
     */
    public function signup()
    {
        return view('auth.register');
    }

    /**
     *
     * @return \Illuminate\Http\RedirectResponse
     */
    
     public function register()
     {
     
        /* $validator = Validator::make(Input::only('g-recaptcha-response'), [
        'g-recaptcha-response' => 'required|captcha'
       ]);
     
       if ($validator->fails()) {
       return redirect()->route('signup')
       ->exceptInput('g-recaptcha-response')
       ->withErrors($validator->errors());
       } */
      
       //$data = Session::get('githubData');
       $data['ip'] = Request::ip();
       $data['name'] = Input::get('name');
       $data['email'] = Input::get('email');
       $data['password'] = bcrypt(Input::get('password'));
      
       return $this->userCreator->create($this, $data);
       }
     
    
    /**
     * Confirms a user's email address
     *
     * @param string $code            
     * @return \Illuminate\Http\RedirectResponse
     */
    public function confirmEmail($code)
    {
        if (! $user = $this->users->getByConfirmationCode($code)) {
            abort(404);
        }
        
        $user->confirmed = 1;
        $user->confirmation_code = null;
        $user->save();
        
        Auth::login($user, true);
        
        session([
            'success' => 'Your email was successfully confirmed.'
        ]);
        
        return redirect()->home();
    }

    /**
     * Re-sends the confirmation email
     *
     * @return \Illuminate\Http\RedirectResponse
     */
    public function resendEmailConfirmation()
    {
        $this->confirmation->send(Auth::user());
        
        session([
            'success' => 'A new email confirmation was sent to ' . Auth::user()->email
        ]);
        
        return redirect()->home();
    }

    /**
     *
     * @return \Illuminate\Http\RedirectResponse
     */
    public function logout()
    {
        Auth::logout();
        
        return redirect()->home();
    }

    /**
     * Get the post register / login redirect path.
     *
     * @return string
     */
    public function redirectPath()
    {
        if (property_exists($this, 'redirectPath')) {
            return $this->redirectPath;
        }
        
        return property_exists($this, 'redirectTo') ? $this->redirectTo : '/';
    }

    /**
     *
     * @param
     *            $errors
     * @return \Illuminate\Http\RedirectResponse
     */
    public function userValidationError($errors)
    {
        return $this->redirectBack([
            'errors' => $errors
        ]);
    }

    /**
     *
     * @param \Lio\Accounts\User $user            
     * @return \Illuminate\Http\RedirectResponse
     */
    public function userCreated($user)
    {
        Session::put('success', 'Account created. An email confirmation was sent to ' . $user->email);
        
        Auth::login($user, true);
        
        return $this->redirectIntended(route('home'));
    }
}
