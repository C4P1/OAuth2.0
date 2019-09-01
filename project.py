#!/usr/bin/env python3

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    jsonify,
    url_for,
    flash
)


from sqlalchemy import create_engine, asc, desc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Category, Item, User

from flask import session as login_session
import random
import string

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

app = Flask(__name__)

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Item Catalog Project"


engine = create_engine('sqlite:///itemcatalog.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


@app.route('/gconnect', methods=['POST'])
def gconnect():
    """
    Function to authorise the user using the token and check token validity.
    Also adds token and user details to the session.
    """
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print("Token's client ID does not match app's.")
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps(
            'Current user is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['email'] = data['email']

    # See if a user exists, if it doesn't make a new one
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    flash("Logged in as %s" % login_session['username'])
    print("done!")
    return output


# USER HELPER FUNCTIONS


def createUser(login_session):
    """
    Creates a new user in the database.

    Args:
        login_session: An object with session data

    Returns:
        user.id: The unique ID associated with the new user in the database.
    """
    newUser = User(name=login_session['username'], email=login_session[
                   'email'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    """
    Fetches user information from the database.

    Args:
        user_id: Unique ID for the user.

    Returns:
        user: Object containing all user data.
    """
    user = session.query(User).filter_by(id=user_id).first()
    return user


def getUserID(email):
    """
    Fetches user ID from database based on email provided.

    Args:
        email: Email of the user to be fetched.

    Returns:
        user.id: The unique ID associated with the new user in the database.
    """
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


# DISCONNECT AND REVOKE TOKEN
@app.route('/gdisconnect')
def gdisconnect():
    """
    Disconnects the user, revokes the access token and clears session data.
    """
    # Only disconnect a connected user.
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]

    if result['status'] == '200':
        # Reset the user's session.
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']

        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return redirect('/')
    else:
        response = make_response(
            json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


# SHOW MAIN PAGE
@app.route('/')
def showMainPage():
    """
    Creates a randomised state token and shows the front page to the user.
    """
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)


# VIEW ENTIRE CATALOG
@app.route('/catalog/')
def viewCatalog():
    """
    Redirects the user to the catalog page.
    """
    categories = session.query(Category).order_by(asc(Category.id))
    items = session.query(Item).order_by(desc(Item.id)).limit(9)
    return render_template('catalog.html', items=items, categories=categories)


# VIEW CATEGORY DETAILS
@app.route('/category/<int:category_id>/')
def viewCategory(category_id):
    """
    Displays a page containing all items belonging to the same category.

    Args:
        category_id: ID of the category whose items are to be displayed.

    Returns:
        A page displaying all items in the category.
    """
    category = session.query(Category).filter_by(id=category_id).one()
    items = session.query(Item).filter_by(category_id=category_id).all()
    return render_template('category.html', category=category, items=items)


# VIEW ITEM DETAILS
@app.route('/item/<int:item_id>/')
def viewItem(item_id):
    """
    Displays a page containing all details of a specific item.

    Args:
        item_id: ID of the item whose details are to be displayed.

    Returns:
        A page displaying all details of the item.
    """
    item = session.query(Item).filter_by(id=item_id).one()
    return render_template('item.html', item=item)


# ADD NEW ITEM
@app.route('/item/new/', methods=['GET', 'POST'])
def newItem():
    """
    Adds a new item to the database.

    Returns:
        On GET: Redirects to a page where the user can enter the details of
        the new item to be added.
        On POST: Checks if the item details are valid, then commits them to
        the database
        On either: If the user is not logged in, redirects to the main page.
    """
    if 'username' not in login_session:
        return redirect('/')
    if request.method == 'POST':
        newItem = Item(name=request.form['name'].strip(),
                       description=request.form['description'].strip(),
                       category_id=request.form['category'],
                       user_id=login_session['user_id'])
        if newItem.name == '' or newItem.description == '':
            flash("Please enter valid details.")
            return redirect(request.url)
        else:
            session.add(newItem)
            session.commit()
            flash('%s added under the %s category'
                  % (newItem.name, newItem.category.name))
            return redirect(url_for('viewCatalog'))
    else:
        categories = session.query(Category).order_by(asc(Category.name))
        return render_template('newitem.html', categories=categories)


# EDIT EXISTING ITEMS
@app.route('/item/<int:item_id>/edit/', methods=['GET', 'POST'])
def editItem(item_id):
    """
    Edits an existing item.

    Args:
        item_id: Unique ID of the item to be edited.

    Returns:
        On GET: Checks if the user has authorisation to edit this item.
        Redirects to a page where the user can edit the details of
        the item or flashes an error message accordingly.
        On POST: Checks if the item details are valid, then commits them to
        the database
        On either: If the user is not logged in, redirects to the main page.
    """
    if 'username' not in login_session:
        return redirect('/')
    editedItem = session.query(Item).filter_by(id=item_id).one()

    if request.method == 'POST':
        if request.form['name']:
            editedItem.name = request.form['name'].strip()
        if request.form['description']:
            editedItem.description = request.form['description'].strip()
        if request.form['category']:
            editedItem.course = request.form['category']

        if editedItem.name == '' or editedItem.description == '':
            flash("Please enter valid details.")
            return redirect(request.url)

        session.add(editedItem)
        session.commit()
        flash('Item Successfully Edited')
        return redirect(url_for('viewCatalog'))
    else:
        if editedItem.user.name != login_session['username']:
            flash("You are not authorised to edit this item!")
            return redirect('item/%s/' % item_id)
        categories = session.query(Category).order_by(asc(Category.name))
        return render_template('edititem.html',
                               item=editedItem, categories=categories)


# DELETE AN ITEM
@app.route('/item/<int:item_id>/delete/', methods=['GET', 'POST'])
def deleteItem(item_id):
    """
    Deletes an existing item.

    Args:
        item_id: Unique ID of the item to be deleted.

    Returns:
        On GET: Checks if the user has authorisation to delete this item.
        Redirects to a confirmation page or flashes an error message
        accordingly.
        On POST: Deletes the item from the database.
        On either: If the user is not logged in, redirects to the main page.
    """
    if 'username' not in login_session:
        return redirect('/')
    itemToDelete = session.query(Item).filter_by(id=item_id).one()
    if request.method == 'POST':
        session.delete(itemToDelete)
        session.commit()
        flash('%s was successfully deleted. Bye bye %s.'
              % (itemToDelete.name, itemToDelete.name))
        return redirect(url_for('viewCatalog'))
    else:
        if itemToDelete.user.name != login_session['username']:
            flash("You are not authorised to delete this item!")
            return redirect('item/%s/' % item_id)
        return render_template('deleteItem.html', item=itemToDelete)


# ENDPOINTS


# JSON FOR CATEGORY ITEMS
@app.route('/category/<int:category_id>/JSON')
def categoryItemsJSON(category_id):
    """
    Returns the details of all items in a category as JSON

    Args:
        category_id: Unique ID of the category to be fetched.

    Returns:
        JSON object containing all items in the category.
    """
    category = session.query(Category).filter_by(id=category_id).one()
    items = session.query(Item).filter_by(category_id=category_id).all()
    return jsonify(Items=[i.serialize for i in items])


# JSON FOR ALL ITEMS
@app.route('/items/JSON')
def allItemsJSON():
    """
    Returns the details of all items in the database as JSON.

    Returns:
        JSON object containing all items in the database.
    """
    items = session.query(Item).all()
    return jsonify(Items=[i.serialize for i in items])


# JSON FOR ONE ITEMS
@app.route('/item/<int:item_id>/JSON')
def itemJSON(item_id):
    """
    Returns the details of a specific item as JSON.

    Args:
        item_id: Unique ID of the item to be fetched.

    Returns:
        JSON object containing all details of the item.
    """
    item = session.query(Item).filter_by(id=item_id).one()
    return jsonify(item.serialize)


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000, threaded=False)
