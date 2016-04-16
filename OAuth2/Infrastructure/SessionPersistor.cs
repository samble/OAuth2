using System;
using System.Collections;
using System.Linq;
using System.Web;
using System.Web.SessionState;

namespace OAuth2.Infrastructure
{
    /// <summary>
    /// Suitable for use as a generic persistence class, using Session for storage
    /// </summary>
    public class SessionPersistor : IDictionary
    {
        private readonly HttpSessionStateBase mySession;

        public SessionPersistor() : this (HttpContext.Current.Session) { }

        public SessionPersistor(HttpSessionState session)
        {
            mySession = new HttpSessionStateWrapper(session);
        }

        public object this[object key]
        {
            get
            {
                if (key is int)
                {
                    return mySession[(int)key];
                }
                return mySession[key as string];
            }

            set
            {
                if (key is int)
                {
                    mySession[(int)key] = value;
                }
                if (key is string)
                {
                    mySession[key as string] = value;
                }
                else throw new NotImplementedException("SessionPersistor supports only int and string keys");

            }
        }

        public int Count
        {
            get
            {
                return mySession.Count;
            }
        }

        public bool IsFixedSize
        {
            get
            {
                return false;
            }
        }

        public bool IsReadOnly
        {
            get
            {
                return mySession.IsReadOnly;
            }
        }

        public bool IsSynchronized
        {
            get
            {
                return mySession.IsSynchronized;
            }
        }

        public ICollection Keys
        {
            get
            {
                return mySession.Keys;
            }
        }

        public object SyncRoot
        {
            get
            {
                return mySession.SyncRoot;
            }
        }

        public ICollection Values
        {
            get
            {
                throw new NotImplementedException();
            }
        }

        public void Add(object key, object value)
        {
            if (this[key] != null)
            {
                throw new ArgumentException("Key already exists", key as string);
            }
            this[key] = value;
        }

        public void Clear()
        {
            mySession.Clear();
        }

        public bool Contains(object key)
        {
            return this[key] != null;
        }

        public void CopyTo(Array array, int index)
        {
            mySession.CopyTo(array, index);
        }

        public IDictionaryEnumerator GetEnumerator()
        {
            //Only if I absolutely have to. Who enumerates over a session?
            throw new NotImplementedException();
        }

        public void Remove(object key)
        {
            this[key] = null;
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return mySession.GetEnumerator();
        }
    }
}