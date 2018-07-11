import org.snmp4j.util.CommonTimer;
import org.snmp4j.util.TimerFactory;

import java.util.Date;
import java.util.Timer;
import java.util.TimerTask;

/**
 * A customized timer factory for Snmp class.
 * This used a shared thread pool to avoid to many threads created per Snmp object
 */
public class LMTimerFactory implements TimerFactory {

    private static final TimerAdapter _TIMER_ADAPTER = new TimerAdapter();

    public CommonTimer createTimer() {
        return _TIMER_ADAPTER;
    }

    /**
     * a CommonTimer to override the default implementation in order to avoid create a timer every time.
     * We used a Timer array instead of a {@link java.util.concurrent.ScheduledExecutorService}
     * this is because the schedule method will change the state of related TimerTask to SCHEDULED
     * but when you use the ScheduledExecutorService it will not.
     * <p>
     * If use ScheduledExecutorService, it will cause the timeout not work as expected.
     *
     * @see org.snmp4j.util.DefaultTimerFactory.TimerAdapter
     */
    static class TimerAdapter implements CommonTimer {

        private final Timer[] timers;


        public TimerAdapter() {
            int threadCount = 4;
            if (threadCount <= 0) {
                threadCount = 4;
            }
            timers = new Timer[threadCount];
            for (int i = 0; i < threadCount; i++) {
                timers[i] = new Timer("snmp-timer-" + i, true);
            }
        }

        public void schedule(TimerTask task, long delay) {
            _getTimer(task).schedule(task, delay);
        }

        private Timer _getTimer(TimerTask task) {
            return timers[Math.abs(task.hashCode() % timers.length)];
        }

        /**
         * Be careful with this method, this will cause the whole timer shutdown...
         */
        public void cancel() {
        }

        /**
         * not used for now...
         */
        public void schedule(TimerTask task, Date firstTime, long period) {
            try {
                _getTimer(task).schedule(task, firstTime, period);
            } catch (Throwable e) {
                e.printStackTrace();
            }
        }

        /**
         * not used for now...
         */
        public void schedule(TimerTask task, long delay, long period) {
            try {
                _getTimer(task).schedule(task, delay, period);
            } catch (Throwable e) {
                e.printStackTrace();
            }
        }
    }

}

