// created on 10/5/2002 at 23:01
// Npgsql.NpgsqlConnection.cs
//
// Author:
//    Francisco Jr. (fxjrlists@yahoo.com.br)
//
//    Copyright (C) 2002 The Npgsql Development Team
//    npgsql-general@gborg.postgresql.org
//    http://gborg.postgresql.org/project/npgsql/projdisplay.php
//
//
// Permission to use, copy, modify, and distribute this software and its
// documentation for any purpose, without fee, and without a written
// agreement is hereby granted, provided that the above copyright notice
// and this paragraph and the following two paragraphs appear in all copies.
//
// IN NO EVENT SHALL THE NPGSQL DEVELOPMENT TEAM BE LIABLE TO ANY PARTY
// FOR DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES,
// INCLUDING LOST PROFITS, ARISING OUT OF THE USE OF THIS SOFTWARE AND ITS
// DOCUMENTATION, EVEN IF THE NPGSQL DEVELOPMENT TEAM HAS BEEN ADVISED OF
// THE POSSIBILITY OF SUCH DAMAGE.
//
// THE NPGSQL DEVELOPMENT TEAM SPECIFICALLY DISCLAIMS ANY WARRANTIES,
// INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
// AND FITNESS FOR A PARTICULAR PURPOSE. THE SOFTWARE PROVIDED HEREUNDER IS
// ON AN "AS IS" BASIS, AND THE NPGSQL DEVELOPMENT TEAM HAS NO OBLIGATIONS
// TO PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR MODIFICATIONS.

using System;
using System.ComponentModel;
using System.Data;
using System.Data.Common;
using System.Net.Security;
using System.Reflection;
using System.Resources;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Transactions;
using Mono.Security.Protocol.Tls;
using IsolationLevel = System.Data.IsolationLevel;

namespace Npgsql
{
    /// <summary>
    /// Represents the method that handles the <see cref="Npgsql.NpgsqlConnection.Notification">Notice</see> events.
    /// </summary>
    /// <param name="sender">The source of the event.</param>
    /// <param name="e">A <see cref="Npgsql.NpgsqlNoticeEventArgs">NpgsqlNoticeEventArgs</see> that contains the event data.</param>
    public delegate void NoticeEventHandler(Object sender, NpgsqlNoticeEventArgs e);
    /// <summary>
    /// Represents the method that handles the <see cref="Npgsql.NpgsqlConnection.Notification">Notification</see> events.
    /// </summary>
    /// <param name="sender">The source of the event.</param>
    /// <param name="e">A <see cref="Npgsql.NpgsqlNotificationEventArgs">NpgsqlNotificationEventArgs</see> that contains the event data.</param>
    public delegate void NotificationEventHandler(Object sender, NpgsqlNotificationEventArgs e);

    /// <summary>
    /// This class represents a connection to a
    /// PostgreSQL server.
    /// </summary>
#if WITHDESIGN
    [System.Drawing.ToolboxBitmapAttribute(typeof(NpgsqlConnection))]
#else
    [System.ComponentModel.DesignerCategory("Code")]
#endif
    public sealed class NpgsqlConnection : DbConnection, ICloneable
    {
        #region Statics
        // Logging related values
        private static readonly String CLASSNAME = MethodBase.GetCurrentMethod().DeclaringType.Name;
        private static readonly ResourceManager resman = new ResourceManager(MethodBase.GetCurrentMethod().DeclaringType);
        // Parsed connection string cache
        private static readonly Cache<NpgsqlConnectionStringBuilder> cache = new Cache<NpgsqlConnectionStringBuilder>();
        #endregion

        #region Events
        /// <summary>
        /// Occurs on NoticeResponses from the PostgreSQL backend.
        /// </summary>
        public event NoticeEventHandler Notice;
        /// <summary>
        /// Occurs on NotificationResponses from the PostgreSQL backend.
        /// </summary>
        public event NotificationEventHandler Notification;
        /// <summary>
        /// Called to provide client certificates for SSL handshake.
        /// </summary>
        public event ProvideClientCertificatesCallback ProvideClientCertificatesCallback;
        /// <summary>
        /// Called to validate server's certificate during SSL handshake
        /// </summary>
        public event ValidateRemoteCertificateCallback ValidateRemoteCertificateCallback;
        /// <summary>
        /// Mono.Security.Protocol.Tls.CertificateSelectionCallback delegate.
        /// </summary>
        [Obsolete("CertificateSelectionCallback, CertificateValidationCallback and PrivateKeySelectionCallback have been replaced with ValidateRemoteCertificateCallback.")]
        public event CertificateSelectionCallback CertificateSelectionCallback;
        /// <summary>
        /// Mono.Security.Protocol.Tls.CertificateValidationCallback delegate.
        /// </summary>
        [Obsolete("CertificateSelectionCallback, CertificateValidationCallback and PrivateKeySelectionCallback have been replaced with ValidateRemoteCertificateCallback.")]
        public event CertificateValidationCallback CertificateValidationCallback;
        /// <summary>
        /// Mono.Security.Protocol.Tls.PrivateKeySelectionCallback delegate.
        /// </summary>
        [Obsolete("CertificateSelectionCallback, CertificateValidationCallback and PrivateKeySelectionCallback have been replaced with ValidateRemoteCertificateCallback.")]
        public event PrivateKeySelectionCallback PrivateKeySelectionCallback;
        #endregion

        #region Delegate Instances
        internal NoticeEventHandler NoticeDelegate;
        internal NotificationEventHandler NotificationDelegate;
        internal ProvideClientCertificatesCallback ProvideClientCertificatesCallbackDelegate;
        internal CertificateSelectionCallback CertificateSelectionCallbackDelegate;
        internal CertificateValidationCallback CertificateValidationCallbackDelegate;
        internal PrivateKeySelectionCallback PrivateKeySelectionCallbackDelegate;
        internal ValidateRemoteCertificateCallback ValidateRemoteCertificateCallbackDelegate;
        #endregion

        #region Members
        private bool _disposed;             // Set this when disposed is called.
        private bool _fakingOpen;           // Used when we closed the connector due to an error, but are pretending it's open.
        private bool _postponingClose;      // Used when the connection is closed but an TransactionScope is still active(the actual close is postponed until the scope ends)
        private bool _postponingDispose;
        private NpgsqlConnectionStringBuilder _settings; // Strongly-typed ConnectionString values
        private NpgsqlConnector _connector;              // Connector being used for the active connection.
        private NpgsqlPromotableSinglePhaseNotification _promotable;
        private string _connectionString;               // A cached copy of the result of `settings.ConnectionString`
        #endregion


        /// <summary>
        /// Initializes a new instance of the
        /// <see cref="Npgsql.NpgsqlConnection">NpgsqlConnection</see> class.
        /// </summary>
        public NpgsqlConnection()
            : this(String.Empty)
        {
        }


        /// <summary>
        /// Initializes a new instance of the
        /// <see cref="Npgsql.NpgsqlConnection">NpgsqlConnection</see> class
        /// and sets the <see cref="Npgsql.NpgsqlConnection.ConnectionString">ConnectionString</see>.
        /// </summary>
        /// <param name="connectionString">The connection used to open the PostgreSQL database.</param>
        public NpgsqlConnection(String connectionString)
        {
            NpgsqlEventLog.LogMethodEnter(LogLevel.Debug, CLASSNAME, CLASSNAME, "NpgsqlConnection()");

            LoadConnectionStringBuilder(connectionString);
            Init();
        }


        /// <summary>
        /// Initializes a new instance of the
        /// <see cref="Npgsql.NpgsqlConnection">NpgsqlConnection</see> class
        /// and sets the <see cref="Npgsql.NpgsqlConnection.ConnectionString">ConnectionString</see>.
        /// </summary>
        /// <param name="connectionString">The connection used to open the PostgreSQL database.</param>
        public NpgsqlConnection(NpgsqlConnectionStringBuilder connectionString)
        {
            NpgsqlEventLog.LogMethodEnter(LogLevel.Debug, CLASSNAME, CLASSNAME, "NpgsqlConnection()");

            LoadConnectionStringBuilder(connectionString);
            Init();
        }


        /// <summary>
        /// Begins a database transaction.
        /// </summary>
        /// <returns>A <see cref="Npgsql.NpgsqlTransaction">NpgsqlTransaction</see>
        /// object representing the new transaction.</returns>
        /// <remarks>
        /// Currently there's no support for nested transactions.
        /// </remarks>
        public new NpgsqlTransaction BeginTransaction()
        {
            NpgsqlEventLog.LogMethodEnter(LogLevel.Debug, CLASSNAME, "BeginTransaction");
            return this.BeginTransaction(IsolationLevel.ReadCommitted);
        }


        /// <summary>
        /// Begins a database transaction with the specified isolation level.
        /// </summary>
        /// <param name="level">The <see cref="System.Data.IsolationLevel">isolation level</see> under which the transaction should run.</param>
        /// <returns>A <see cref="Npgsql.NpgsqlTransaction">NpgsqlTransaction</see>
        /// object representing the new transaction.</returns>
        /// <remarks>
        /// Currently the IsolationLevel ReadCommitted and Serializable are supported by the PostgreSQL backend.
        /// There's no support for nested transactions.
        /// </remarks>
        public new NpgsqlTransaction BeginTransaction(IsolationLevel level)
        {
            NpgsqlEventLog.LogMethodEnter(LogLevel.Debug, CLASSNAME, "BeginTransaction", level);

            CheckConnectionOpen();
            if (_connector.Transaction != null)
            {
                throw new InvalidOperationException(resman.GetString("Exception_NoNestedTransactions"));
            }
            return new NpgsqlTransaction(this, level);
        }


        /// <summary>
        /// Opens a database connection with the property settings specified by the
        /// <see cref="Npgsql.NpgsqlConnection.ConnectionString">ConnectionString</see>.
        /// </summary>
        public override void Open()
        {
            // If we're postponing a close (see doc on this variable), the connection is already
            // open and can be silently reused
            if(_postponingClose)
            {
                return;
            }
            CheckConnectionClosed();

            NpgsqlEventLog.LogMethodEnter(LogLevel.Debug, CLASSNAME, "Open");

            // Check if there is any missing argument.
            if(!_settings.ContainsKey(Keywords.Host))
            {
                throw new ArgumentException(resman.GetString("Exception_MissingConnStrArg"),
                                            Keywords.Host.ToString());
            }
            if(!_settings.ContainsKey(Keywords.UserName) && !_settings.ContainsKey(Keywords.IntegratedSecurity))
            {
                throw new ArgumentException(resman.GetString("Exception_MissingConnStrArg"),
                                            Keywords.UserName.ToString());
            }

            // Get a Connector, either from the pool or creating one ourselves.
            if(this.Pooling)
            {
                _connector = NpgsqlConnectorPool.ConnectorPoolMgr.RequestConnector(this);
            }
            else
            {
                _connector = new NpgsqlConnector(this);

                _connector.ProvideClientCertificatesCallback += ProvideClientCertificatesCallbackDelegate;
                _connector.CertificateSelectionCallback += CertificateSelectionCallbackDelegate;
                _connector.CertificateValidationCallback += CertificateValidationCallbackDelegate;
                _connector.PrivateKeySelectionCallback += PrivateKeySelectionCallbackDelegate;
                _connector.ValidateRemoteCertificateCallback += ValidateRemoteCertificateCallbackDelegate;

                _connector.Open();
            }

            _connector.Notice += NoticeDelegate;
            _connector.Notification += NotificationDelegate;
            if(this.SyncNotification)
            {
                _connector.AddNotificationThread();
            }
            if(_settings.Enlist)
            {
                this.Promotable.Enlist(Transaction.Current);
            }

            this.OnStateChange(new StateChangeEventArgs(ConnectionState.Closed, ConnectionState.Open));
        }


        /// <summary>
        /// This method changes the current database by disconnecting from the actual
        /// database and connecting to the specified.
        /// </summary>
        /// <param name="dbName">The name of the database to use in place of the current database.</param>
        public override void ChangeDatabase(String dbName)
        {
            CheckNotDisposed();

            NpgsqlEventLog.LogMethodEnter(LogLevel.Debug, CLASSNAME, "ChangeDatabase", dbName);
            if(dbName == null)
            {
                throw new ArgumentNullException("dbName");
            }
            if (string.IsNullOrEmpty(dbName))
            {
                throw new ArgumentOutOfRangeException("dbName", dbName, String.Format(resman.GetString("Exception_InvalidDbName")));
            }

            Close();
            
            // Mutating the current `settings` object would invalidate the cached instance, so work on a copy instead.
            _settings = _settings.Clone();
            _settings[Keywords.Database] = dbName;
            _connectionString = null;
            Open();
        }


        /// <summary>
        /// Releases the connection to the database.  If the connection is pooled, it will be
        ///    made available for re-use.  If it is non-pooled, the actual connection will be shutdown.
        /// </summary>
        public override void Close()
        {
            NpgsqlEventLog.LogMethodEnter(LogLevel.Debug, CLASSNAME, "Close");

            if(_connector == null)
            {
                return;
            }
            if(_promotable != null && _promotable.InLocalTransaction)
            {
                _postponingClose = true;
                return;
            }

            ReallyClose();
        }


        /// <summary>
        /// Creates and returns a <see cref="Npgsql.NpgsqlCommand">NpgsqlCommand</see>
        /// object associated with the <see cref="Npgsql.NpgsqlConnection">NpgsqlConnection</see>.
        /// </summary>
        /// <returns>A <see cref="Npgsql.NpgsqlCommand">NpgsqlCommand</see> object.</returns>
        public new NpgsqlCommand CreateCommand()
        {
            CheckNotDisposed();

            NpgsqlEventLog.LogMethodEnter(LogLevel.Debug, CLASSNAME, "CreateCommand");
            return new NpgsqlCommand(string.Empty, this);
        }


        /// <summary>
        /// Create a new connection based on this one.
        /// </summary>
        /// <returns>A new NpgsqlConnection object.</returns>
        public NpgsqlConnection Clone()
        {
            CheckNotDisposed();

            NpgsqlConnection clone = new NpgsqlConnection(this.ConnectionString);

            clone.Notice += this.Notice;
            if(_connector != null)
            {
                clone.Open();
            }
            return clone;
        }


        /// <summary>
        /// Returns the supported collections
        /// </summary>
        public override DataTable GetSchema()
        {
            return NpgsqlSchema.GetMetaDataCollections();
        }


        /// <summary>
        /// Returns the schema collection specified by the collection name.
        /// </summary>
        /// <param name="collectionName">The collection name.</param>
        /// <returns>The collection specified.</returns>
        public override DataTable GetSchema(string collectionName)
        {
            return GetSchema(collectionName, null);
        }

        /// <summary>
        /// Returns the schema collection specified by the collection name filtered by the restrictions.
        /// </summary>
        /// <param name="collectionName">The collection name.</param>
        /// <param name="restrictions">
        /// The restriction values to filter the results.  A description of the restrictions is contained
        /// in the Restrictions collection.
        /// </param>
        /// <returns>The collection specified.</returns>
        public override DataTable GetSchema(string collectionName, string[] restrictions)
        {
            using(var tempConn = new NpgsqlConnection(ConnectionString))
            {
                switch (collectionName)
                {
                    case "MetaDataCollections":
                        return NpgsqlSchema.GetMetaDataCollections();
                    case "Restrictions":
                        return NpgsqlSchema.GetRestrictions();
                    case "DataSourceInformation":
                        return NpgsqlSchema.GetDataSourceInformation();
                    case "DataTypes":
                        throw new NotSupportedException();
                    case "ReservedWords":
                        return NpgsqlSchema.GetReservedWords();
                        // custom collections for npgsql
                    case "Databases":
                        return NpgsqlSchema.GetDatabases(tempConn, restrictions);
                    case "Schemata":
                        return NpgsqlSchema.GetSchemata(tempConn, restrictions);
                    case "Tables":
                        return NpgsqlSchema.GetTables(tempConn, restrictions);
                    case "Columns":
                        return NpgsqlSchema.GetColumns(tempConn, restrictions);
                    case "Views":
                        return NpgsqlSchema.GetViews(tempConn, restrictions);
                    case "Users":
                        return NpgsqlSchema.GetUsers(tempConn, restrictions);
                    case "Indexes":
                        return NpgsqlSchema.GetIndexes(tempConn, restrictions);
                    case "IndexColumns":
                        return NpgsqlSchema.GetIndexColumns(tempConn, restrictions);
                    case "Constraints":
                    case "PrimaryKey":
                    case "UniqueKeys":
                    case "ForeignKeys":
                        return NpgsqlSchema.GetConstraints(tempConn, restrictions, collectionName);
                    case "ConstraintColumns":
                        return NpgsqlSchema.GetConstraintColumns(tempConn, restrictions);
                    default:
                        throw new ArgumentOutOfRangeException("collectionName", collectionName, "Invalid collection name");
                }
            }
        }


        /// <summary>
        /// Clear connection pool.
        /// </summary>
        public void ClearPool()
        {
            NpgsqlConnectorPool.ConnectorPoolMgr.ClearPool(this);
        }


        /// <summary>
        /// Clear all connection pools.
        /// </summary>
        public static void ClearAllPools()
        {
            NpgsqlConnectorPool.ConnectorPoolMgr.ClearAllPools();
        }


        /// <summary>
        /// Enlist transation.
        /// </summary>
        /// <param name="transaction"></param>
        public override void EnlistTransaction(Transaction transaction)
        {
            this.Promotable.Enlist(transaction);
        }


        /// <summary>
        /// Called from DataReader when thread is in abort state, to signal the connection open check to reopen the connector. 
        /// </summary>
        internal void EmergencyClose()
        {
            _fakingOpen = true;
        }


        /// <summary>
        /// When a connection is closed within an enclosing TransactionScope and the transaction
        /// hasn't been promoted, we defer the actual closing until the scope ends.
        /// </summary>
        internal void PromotableLocalTransactionEnded()
        {
            NpgsqlEventLog.LogMethodEnter(LogLevel.Debug, CLASSNAME, "PromotableLocalTransactionEnded");
            if(_postponingDispose)
            {
                Dispose(true);
            }
            else
            {
                if(_postponingClose)
                {
                    ReallyClose();
                }
            }
        }


        /// <summary>
        /// Returns a copy of the NpgsqlConnectionStringBuilder that contains the parsed connection string values.
        /// </summary>
        internal NpgsqlConnectionStringBuilder CopyConnectionStringBuilder()
        {
            return _settings.Clone();
        }


        /// <summary>
        /// Default SSL CertificateSelectionCallback implementation.
        /// </summary>
        internal X509Certificate DefaultCertificateSelectionCallback(X509CertificateCollection clientCertificates,
                                                                     X509Certificate serverCertificate, string targetHost,
                                                                     X509CertificateCollection serverRequestedCertificates)
        {
            if(CertificateSelectionCallback != null)
            {
                return CertificateSelectionCallback(clientCertificates, serverCertificate, targetHost, serverRequestedCertificates);
            }
            return null;
        }

        
        /// <summary>
        /// Default SSL CertificateValidationCallback implementation.
        /// </summary>
        internal bool DefaultCertificateValidationCallback(X509Certificate certificate, int[] certificateErrors)
        {
            if(CertificateValidationCallback != null)
            {
                return CertificateValidationCallback(certificate, certificateErrors);
            }
            return true;
        }


        /// <summary>
        /// Default SSL PrivateKeySelectionCallback implementation.
        /// </summary>
        internal AsymmetricAlgorithm DefaultPrivateKeySelectionCallback(X509Certificate certificate, string targetHost)
        {
            if(PrivateKeySelectionCallback != null)
            {
                return PrivateKeySelectionCallback(certificate, targetHost);
            }
            return null;
        }


        /// <summary>
        /// Default SSL ProvideClientCertificatesCallback implementation.
        /// </summary>
        internal void DefaultProvideClientCertificatesCallback(X509CertificateCollection certificates)
        {
            if(ProvideClientCertificatesCallback != null)
            {
                ProvideClientCertificatesCallback(certificates);
            }
        }


        /// <summary>
        /// Default SSL ValidateRemoteCertificateCallback implementation.
        /// </summary>
        internal bool DefaultValidateRemoteCertificateCallback(X509Certificate cert, X509Chain chain, SslPolicyErrors errors)
        {
            if(ValidateRemoteCertificateCallback != null)
            {
                return ValidateRemoteCertificateCallback(cert, chain, errors);
            }
            return true;
        }


        /// <summary>
        /// Creates and returns a <see cref="System.Data.Common.DbCommand">DbCommand</see>
        /// object associated with the <see cref="System.Data.Common.DbConnection">IDbConnection</see>.
        /// </summary>
        /// <returns>A <see cref="System.Data.Common.DbCommand">DbCommand</see> object.</returns>
        protected override DbCommand CreateDbCommand()
        {
            NpgsqlEventLog.LogMethodEnter(LogLevel.Debug, CLASSNAME, "CreateDbCommand");
            return CreateCommand();
        }
        

        /// <summary>
        /// Releases all resources used by the
        /// <see cref="Npgsql.NpgsqlConnection">NpgsqlConnection</see>.
        /// </summary>
        /// <param name="disposing"><b>true</b> when called from Dispose();
        /// <b>false</b> when being called from the finalizer.</param>
        protected override void Dispose(bool disposing)
        {
            if(_disposed)
            {
                return;
            }

            _postponingDispose = false;
            if(disposing)
            {
                NpgsqlEventLog.LogMethodEnter(LogLevel.Debug, CLASSNAME, "Dispose");
                Close();
                if(_postponingClose)
                {
                    _postponingDispose = true;
                    return;
                }
            }

            base.Dispose(disposing);
            _disposed = true;
        }


        /// <summary>
        /// Begins a database transaction with the specified isolation level.
        /// </summary>
        /// <param name="isolationLevel">The <see cref="System.Data.IsolationLevel">isolation level</see> under which the transaction should run.</param>
        /// <returns>An <see cref="System.Data.Common.DbTransaction">DbTransaction</see>
        /// object representing the new transaction.</returns>
        /// <remarks>
        /// Currently the IsolationLevel ReadCommitted and Serializable are supported by the PostgreSQL backend.
        /// There's no support for nested transactions.
        /// </remarks>
        protected override DbTransaction BeginDbTransaction(IsolationLevel isolationLevel)
        {
            NpgsqlEventLog.LogMethodEnter(LogLevel.Debug, CLASSNAME, "BeginDbTransaction", isolationLevel);
            return BeginTransaction(isolationLevel);
        }


        /// <summary>
        /// Perform the actual close of the connection and clean up of connector usage.
        /// </summary>
        private void ReallyClose()
        {
            NpgsqlEventLog.LogMethodEnter(LogLevel.Debug, CLASSNAME, "ReallyClose");

            _postponingClose = false;

            // clear the way for another promotable transaction
            _promotable = null;

            _connector.Notification -= NotificationDelegate;
            _connector.Notice -= NoticeDelegate;
            if(this.SyncNotification)
            {
                _connector.RemoveNotificationThread();
            }

            if(this.Pooling)
            {
                NpgsqlConnectorPool.ConnectorPoolMgr.ReleaseConnector(this, _connector);
            }
            else
            {
                _connector.ProvideClientCertificatesCallback -= ProvideClientCertificatesCallbackDelegate;
                _connector.CertificateSelectionCallback -= CertificateSelectionCallbackDelegate;
                _connector.CertificateValidationCallback -= CertificateValidationCallbackDelegate;
                _connector.PrivateKeySelectionCallback -= PrivateKeySelectionCallbackDelegate;
                _connector.ValidateRemoteCertificateCallback -= ValidateRemoteCertificateCallbackDelegate;

                if(_connector.Transaction != null)
                {
                    _connector.Transaction.Cancel();
                }
                _connector.Close();
            }
            _connector = null;
            this.OnStateChange(new StateChangeEventArgs(ConnectionState.Open, ConnectionState.Closed));
        }


        /// <summary>
        /// Initializes this instance.
        /// </summary>
        private void Init()
        {
            NoticeDelegate = new NoticeEventHandler(OnNotice);
            NotificationDelegate = new NotificationEventHandler(OnNotification);

            ProvideClientCertificatesCallbackDelegate = new ProvideClientCertificatesCallback(DefaultProvideClientCertificatesCallback);
            CertificateValidationCallbackDelegate = new CertificateValidationCallback(DefaultCertificateValidationCallback);
            CertificateSelectionCallbackDelegate = new CertificateSelectionCallback(DefaultCertificateSelectionCallback);
            PrivateKeySelectionCallbackDelegate = new PrivateKeySelectionCallback(DefaultPrivateKeySelectionCallback);
            ValidateRemoteCertificateCallbackDelegate = new ValidateRemoteCertificateCallback(DefaultValidateRemoteCertificateCallback);

            // Fix authentication problems. See https://bugzilla.novell.com/show_bug.cgi?id=MONO77559 and
            // http://pgfoundry.org/forum/message.php?msg_id=1002377 for more info.
            RSACryptoServiceProvider.UseMachineKeyStore = true;
            _promotable = new NpgsqlPromotableSinglePhaseNotification(this);
        }


        /// <summary>
        /// Write each key/value pair in the connection string to the log.
        /// </summary>
        private void LogConnectionString()
        {
            if(LogLevel.Debug >= NpgsqlEventLog.Level)
            {
                return;
            }
            foreach(string key in _settings.Keys)
            {
                NpgsqlEventLog.LogMsg(resman, "Log_ConnectionStringValues", LogLevel.Debug, key, _settings[key]);
            }
        }


        /// <summary>
        /// Sets the `settings` ConnectionStringBuilder based on the given `connectionString`
        /// </summary>
        /// <param name="connectionString">The connection string to load the builder from</param>
        private void LoadConnectionStringBuilder(string connectionString)
        {
            NpgsqlConnectionStringBuilder newSettings = cache[connectionString];
            if(newSettings == null)
            {
                newSettings = new NpgsqlConnectionStringBuilder(connectionString);
                cache[connectionString] = newSettings;
            }

            LoadConnectionStringBuilder(newSettings);
        }


        /// <summary>
        /// Sets the `settings` ConnectionStringBuilder based on the given `connectionString`
        /// </summary>
        /// <param name="connectionString">The connection string to load the builder from</param>
        private void LoadConnectionStringBuilder(NpgsqlConnectionStringBuilder connectionString)
        {
            // Clone the settings, because if Integrated Security is enabled, user ID can be different
            _settings = connectionString.Clone();

            // Set the UserName explicitly to freeze any Integrated Security-determined names
            if(_settings.IntegratedSecurity)
            {
                _settings.UserName = _settings.UserName;
            }
            RefreshConnectionString();
            LogConnectionString();
        }


        /// <summary>
        /// Refresh the cached _connectionString whenever the builder settings change
        /// </summary>
        private void RefreshConnectionString()
        {
            _connectionString = _settings.ConnectionString;
        }


        /// <summary>
        /// Checks whether the connection is open. With 'open/close' is meant: a connector is present or not.  
        /// </summary>
        /// <exception cref="System.ObjectDisposedException">the connection was already disposed</exception>
        /// <exception cref="System.InvalidOperationException">there's no connector or close was postponed</exception>
        private void CheckConnectionOpen()
        {
            if(_disposed)
            {
                throw new ObjectDisposedException(CLASSNAME);
            }

            if(_fakingOpen)
            {
                if(_connector != null)
                {
                    try
                    {
                        Close();
                    }
                    catch
                    {
                    }
                }
                Open();
                _fakingOpen = false;
            }

            if(_postponingClose || _connector == null)
            {
                throw new InvalidOperationException(resman.GetString("Exception_ConnNotOpen"));
            }
        }


        /// <summary>
        /// Checks whether the connection is closed: if the connector is present, the connection is assumed open. 
        /// </summary>
        /// <exception cref="System.ObjectDisposedException">the connection was already disposed</exception>
        /// <exception cref="System.InvalidOperationException">a connector is present</exception>
        private void CheckConnectionClosed()
        {
            if(_disposed)
            {
                throw new ObjectDisposedException(CLASSNAME);
            }
            if(_connector != null)
            {
                throw new InvalidOperationException(resman.GetString("Exception_ConnOpen"));
            }
        }


        /// <summary>
        /// Checks if the connection is disposed
        /// </summary>
        /// <exception cref="System.ObjectDisposedException">the connection was already disposed.</exception>
        private void CheckNotDisposed()
        {
            if(_disposed)
            {
                throw new ObjectDisposedException(CLASSNAME);
            }
        }

        
        /// <summary>
        /// Raises the Notice event. 
        /// </summary>
        /// <param name="sender">The sender.</param>
        /// <param name="args">The <see cref="NpgsqlNoticeEventArgs"/> instance containing the event data.</param>
        private void OnNotice(object sender, NpgsqlNoticeEventArgs args)
        {
            if(Notice != null)
            {
                Notice(this, args);
            }
        }


        /// <summary>
        /// Raises the notification event
        /// </summary>
        /// <param name="sender">The sender.</param>
        /// <param name="args">The <see cref="NpgsqlNotificationEventArgs"/> instance containing the event data.</param>
        private void OnNotification(object sender, NpgsqlNotificationEventArgs args)
        {
            if(Notification != null)
            {
                Notification(this, args);
            }
        }


        #region IClonable implementation
        /// <summary>
        /// Create a new connection based on this one.
        /// </summary>
        /// <returns>A new NpgsqlConnection object.</returns>
        Object ICloneable.Clone()
        {
            return Clone();
        }
        #endregion

        #region Properties
        /// <summary>
        /// Gets whether this connection is promotable to a distributed connection.
        /// </summary>
        private NpgsqlPromotableSinglePhaseNotification Promotable
        {
            get { return _promotable ?? (_promotable = new NpgsqlPromotableSinglePhaseNotification(this)); }
        }

        /// <summary>
        /// Determine if connection pooling will be used for this connection. 
        /// </summary>
        internal Boolean Pooling
        {
            get { return (_settings.Pooling && (_settings.MaxPoolSize > 0)); }
        }


        /// <summary>
        /// The connector object connected to the backend.
        /// </summary>
        internal NpgsqlConnector Connector
        {
            get { return _connector; }
        }

        /// <summary>
        /// Gets the minimum size of the pool, as set in the strongly-typed connection string values.
        /// </summary>
        internal Int32 MinPoolSize
        {
            get { return _settings.MinPoolSize; }
        }

        /// <summary>
        /// Gets the maximum size of the pool, as set in the strongly-typed connection string values.
        /// </summary>
        internal Int32 MaxPoolSize
        {
            get { return _settings.MaxPoolSize; }
        }

        /// <summary>
        /// Gets the timeout, as set in the strongly-typed connection string values. 
        /// </summary>
        internal Int32 Timeout
        {
            get { return _settings.Timeout; }
        }

        /// <summary>
        /// Use extended types.
        /// </summary>
        public bool UseExtendedTypes
        {
            get { return _settings.UseExtendedTypes; }
        }

        /// <summary>
        /// Backend server host name.
        /// </summary>
        [Browsable(true)]
        public String Host
        {
            get { return _settings.Host; }
        }

        /// <summary>
        /// Backend server port.
        /// </summary>
        [Browsable(true)]
        public Int32 Port
        {
            get { return _settings.Port; }
        }

        /// <summary>
        /// If true, the connection will attempt to use SSL.
        /// </summary>
        [Browsable(true)]
        public Boolean SSL
        {
            get { return _settings.SSL; }
        }

        /// <summary>
        /// Gets or sets a value indicating whether the connection will use a SSL stream (true) 0r not (false)
        /// </summary>
        public Boolean UseSslStream
        {
            get { return NpgsqlConnector.UseSslStream; }
            set { NpgsqlConnector.UseSslStream = value; }
        }

        /// <summary>
        /// Gets the time to wait while trying to establish a connection
        /// before terminating the attempt and generating an error.
        /// </summary>
        /// <value>The time (in seconds) to wait for a connection to open. The default value is 15 seconds.</value>
#if WITHDESIGN
        [NpgsqlSysDescription("Description_ConnectionTimeout", typeof(NpgsqlConnection))]
#endif
        public override Int32 ConnectionTimeout
        {
            get { return _settings.Timeout; }
        }

        /// <summary>
        /// Gets the time to wait while trying to execute a command
        /// before terminating the attempt and generating an error.
        /// </summary>
        /// <value>The time (in seconds) to wait for a command to complete. The default value is 20 seconds.</value>
        public Int32 CommandTimeout
        {
            get { return _settings.CommandTimeout; }
        }

        /// <summary>
        /// Gets the time to wait before closing unused connections in the pool if the count
        /// of all connections exeeds MinPoolSize.
        /// </summary>
        /// <remarks>
        /// If connection pool contains unused connections for ConnectionLifeTime seconds,
        /// the half of them will be closed. If there will be unused connections in a second
        /// later then again the half of them will be closed and so on.
        /// This strategy provide smooth change of connection count in the pool.
        /// </remarks>
        /// <value>The time (in seconds) to wait. The default value is 15 seconds.</value>
        public Int32 ConnectionLifeTime
        {
            get { return _settings.ConnectionLifeTime; }
        }

        ///<summary>
        /// Gets the name of the current database or the database to be used after a connection is opened.
        /// </summary>
        /// <value>The name of the current database or the name of the database to be
        /// used after a connection is opened. The default value is the empty string.</value>
#if WITHDESIGN
        [NpgsqlSysDescription("Description_Database", typeof(NpgsqlConnection))]
#endif
        public override String Database
        {
            get { return _settings.Database; }
        }

        /// <summary>
        /// Whether datareaders are loaded in their entirety (for compatibility with earlier code).
        /// </summary>
        public bool PreloadReader
        {
            get { return _settings.PreloadReader; }
        }

        /// <summary>
        /// Gets the database server name.
        /// </summary>
        public override string DataSource
        {
            get { return _settings.Host; }
        }

        /// <summary>
        /// Gets flag indicating if we are using Synchronous notification or not.
        /// The default value is false.
        /// </summary>
        public Boolean SyncNotification
        {
            get { return _settings.SyncNotification; }
        }

        /// <summary>
        /// Gets the current state of the connection.
        /// </summary>
        /// <value>A bitwise combination of the <see cref="System.Data.ConnectionState">ConnectionState</see> values. The default is <b>Closed</b>.</value>
        [Browsable(false)]
        public ConnectionState FullState
        {
            get
            {
                if(_connector != null && !_disposed)
                {
                    return _connector.State;
                }
                else
                {
                    return ConnectionState.Closed;
                }
            }
        }

        /// <summary>
        /// Gets whether the current state of the connection is Open or Closed
        /// </summary>
        /// <value>ConnectionState.Open or ConnectionState.Closed</value>
        [Browsable(false)]
        public override ConnectionState State
        {
            get
            {
                return (FullState & ConnectionState.Open) == ConnectionState.Open ? ConnectionState.Open : ConnectionState.Closed;
            }
        }

        /// <summary>
        /// Compatibility version.
        /// </summary>
        public Version NpgsqlCompatibilityVersion
        {
            get
            {
                return _settings.Compatible;
            }
        }

        /// <summary>
        /// Version of the PostgreSQL backend.
        /// This can only be called when there is an active connection.
        /// </summary>
        [Browsable(false)]
        public Version PostgreSqlVersion
        {
            get
            {
                CheckConnectionOpen();
                return _connector.ServerVersion;
            }
        }

        /// <summary>
        /// PostgreSQL server version.
        /// </summary>
        public override string ServerVersion
        {
            get { return PostgreSqlVersion.ToString(); }
        }

        /// <summary>
        /// Protocol version in use.
        /// This can only be called when there is an active connection.
        /// Always retuna Version3
        /// </summary>
        [Browsable(false)]
        public ProtocolVersion BackendProtocolVersion
        {
            get
            {
                CheckConnectionOpen();
                return ProtocolVersion.Version3;
            }
        }

        /// <summary>
        /// Process id of backend server.
        /// This can only be called when there is an active connection.
        /// </summary>
        [Browsable(false)]
        public Int32 ProcessID
        {
            get
            {
                CheckConnectionOpen();
                return _connector.BackEndKeyData.ProcessID;
            }
        }

        /// <summary>
        /// Report whether the backend is expecting standard conformant strings.
        /// In version 8.1, Postgres began reporting this value (false), but did not actually support standard conformant strings.
        /// In version 8.2, Postgres began supporting standard conformant strings, but defaulted this flag to false.
        /// As of version 9.1, this flag defaults to true.
        /// </summary>
        [Browsable(false)]
        public Boolean UseConformantStrings
        {
            get
            {
                CheckConnectionOpen();
                return _connector.NativeToBackendTypeConverterOptions.UseConformantStrings;
            }
        }

        /// <summary>
        /// Report whether the backend understands the string literal E prefix (>= 8.1).
        /// </summary>
        [Browsable(false)]
        public Boolean Supports_E_StringPrefix
        {
            get
            {
                CheckConnectionOpen();
                return _connector.NativeToBackendTypeConverterOptions.Supports_E_StringPrefix;
            }
        }

        /// <summary>
        /// Report whether the backend understands the hex byte format (>= 9.0).
        /// </summary>
        [Browsable(false)]
        public Boolean SupportsHexByteFormat
        {
            get
            {
                CheckConnectionOpen();
                return _connector.NativeToBackendTypeConverterOptions.SupportsHexByteFormat;
            }
        }

        /// <summary>
        /// Gets or sets the string used to connect to a PostgreSQL database.
        /// Valid values are:
        /// <ul>
        /// <li>
        /// Server:             Address/Name of Postgresql Server;
        /// </li>
        /// <li>
        /// Port:               Port to connect to;
        /// </li>
        /// <li>
        /// Protocol:           Protocol version to use, instead of automatic; Integer 2 or 3;
        /// </li>
        /// <li>
        /// Database:           Database name. Defaults to user name if not specified;
        /// </li>
        /// <li>
        /// User Id:            User name;
        /// </li>
        /// <li>
        /// Password:           Password for clear text authentication;
        /// </li>
        /// <li>
        /// SSL:                True or False. Controls whether to attempt a secure connection. Default = False;
        /// </li>
        /// <li>
        /// Pooling:            True or False. Controls whether connection pooling is used. Default = True;
        /// </li>
        /// <li>
        /// MinPoolSize:        Min size of connection pool;
        /// </li>
        /// <li>
        /// MaxPoolSize:        Max size of connection pool;
        /// </li>
        /// <li>
        /// Timeout:            Time to wait for connection open in seconds. Default is 15.
        /// </li>
        /// <li>
        /// CommandTimeout:     Time to wait for command to finish execution before throw an exception. In seconds. Default is 20.
        /// </li>
        /// <li>
        /// Sslmode:            Mode for ssl connection control. Can be Prefer, Require, Allow or Disable. Default is Disable. Check user manual for explanation of values.
        /// </li>
        /// <li>
        /// ConnectionLifeTime: Time to wait before closing unused connections in the pool in seconds. Default is 15.
        /// </li>
        /// <li>
        /// SyncNotification:   Specifies if Npgsql should use synchronous notifications.
        /// </li>
        /// <li>
        /// SearchPath: Changes search path to specified and public schemas.
        /// </li>
        /// </ul>
        /// </summary>
        /// <value>The connection string that includes the server name,
        /// the database name, and other parameters needed to establish
        /// the initial connection. The default value is an empty string.
        /// </value>
#if WITHDESIGN
        [RefreshProperties(RefreshProperties.All), DefaultValue(""), RecommendedAsConfigurable(true)]
        [NpgsqlSysDescription("Description_ConnectionString", typeof(NpgsqlConnection)), Category("Data")]
        [Editor(typeof(ConnectionStringEditor), typeof(System.Drawing.Design.UITypeEditor))]
#endif
        public override String ConnectionString
        {
            get
            {
                if(string.IsNullOrEmpty(_connectionString))
                    RefreshConnectionString();
                return _settings.ConnectionString;
            }
            set
            {
                // Connection string is used as the key to the connector.  Because of this,
                // we cannot change it while we own a connector.
                CheckConnectionClosed();
                NpgsqlEventLog.LogPropertySet(LogLevel.Debug, CLASSNAME, "ConnectionString", value);
                NpgsqlConnectionStringBuilder builder = cache[value];
                if(builder == null)
                {
                    _settings = new NpgsqlConnectionStringBuilder(value);
                }
                else
                {
                    _settings = builder.Clone();
                }
                LoadConnectionStringBuilder(value);
            }
        }

#if NET35
        /// <summary>
        /// DB provider factory.
        /// </summary>
        protected override DbProviderFactory DbProviderFactory
        {
            get
            {
                return NpgsqlFactory.Instance;
            }
        }
#endif
        #endregion
    }
}
